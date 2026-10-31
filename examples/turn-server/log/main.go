// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN server with logging.
package main

import (
	"flag"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"syscall"

	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5"
)

// diagnostics deliberately log packet metadata, never TURN credentials or payloads.
type counters struct {
	controlIn, controlOut, controlErrors atomic.Uint64
	channelIn, channelOut atomic.Uint64
	relayIn, relayOut, relayReadErrors, relayWriteErrors atomic.Uint64
}

// stunLogger observes the client-to-TURN listening socket, including ChannelData.
// Logging must never change the outcome of a network operation.
type stunLogger struct {
	net.PacketConn
	stats *counters
	trace bool
}

func (s *stunLogger) observe(direction string, data []byte, peer net.Addr) {
	if stun.IsMessage(data) {
		if direction == "in" {
			s.stats.controlIn.Add(1)
		} else {
			s.stats.controlOut.Add(1)
		}

		msg := &stun.Message{Raw: data}
		if err := msg.Decode(); err != nil {
			log.Printf("TURN_CONTROL_DECODE_ERROR direction=%s peer=%s error=%v", direction, peer, err)
			return
		}
		if msg.Type.Class == stun.ClassErrorResponse {
			s.stats.controlErrors.Add(1)
			var turnErr stun.ErrorCodeAttribute
			if err := turnErr.GetFrom(msg); err == nil {
				log.Printf("TURN_ERROR direction=%s peer=%s method=%v code=%d reason=%q tx=%x",
					direction, peer, msg.Type.Method, turnErr.Code, string(turnErr.Reason), msg.TransactionID)
			} else {
				log.Printf("TURN_ERROR direction=%s peer=%s method=%v decode_error=%v tx=%x",
					direction, peer, msg.Type.Method, err, msg.TransactionID)
			}
		} else if s.trace {
			log.Printf("TURN_CONTROL direction=%s peer=%s method=%v class=%v bytes=%d tx=%x",
				direction, peer, msg.Type.Method, msg.Type.Class, len(data), msg.TransactionID)
		}
		return
	}

	// ChannelData is not STUN, and was invisible to the original example.
	if len(data) >= 4 && data[0]&0xc0 == 0x40 {
		if direction == "in" {
			s.stats.channelIn.Add(1)
		} else {
			s.stats.channelOut.Add(1)
		}
		if s.trace {
			log.Printf("TURN_CHANNEL_DATA direction=%s peer=%s channel=%d payload_bytes=%d",
				direction, peer, binary.BigEndian.Uint16(data[:2]), binary.BigEndian.Uint16(data[2:4]))
		}
	} else if s.trace {
		log.Printf("TURN_UNRECOGNIZED direction=%s peer=%s bytes=%d", direction, peer, len(data))
	}
}

func (s *stunLogger) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := s.PacketConn.WriteTo(p, addr)
	if err != nil {
		log.Printf("TURN_CONTROL_WRITE_ERROR peer=%s bytes=%d error=%v", addr, len(p), err)
	} else {
		s.observe("out", p[:n], addr)
	}
	return n, err
}

func (s *stunLogger) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(p)
	if err == nil {
		s.observe("in", p[:n], addr)
	}
	return n, addr, err
}

// relayLogger wraps each dynamically allocated relay UDP socket. This captures
// both directions, including inbound packets rejected by Pion permissions.
type relayLogger struct {
	net.PacketConn
	stats *counters
	trace bool
}

func (r *relayLogger) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := r.PacketConn.ReadFrom(p)
	if err != nil {
		r.stats.relayReadErrors.Add(1)
		log.Printf("TURN_RELAY_READ_ERROR local=%s error=%v", r.LocalAddr(), err)
	} else {
		r.stats.relayIn.Add(1)
		if r.trace {
			log.Printf("TURN_RELAY_IN local=%s peer=%s bytes=%d", r.LocalAddr(), addr, n)
		}
	}
	return n, addr, err
}

func (r *relayLogger) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := r.PacketConn.WriteTo(p, addr)
	if err != nil {
		r.stats.relayWriteErrors.Add(1)
		log.Printf("TURN_RELAY_WRITE_ERROR local=%s peer=%s bytes=%d error=%v", r.LocalAddr(), addr, len(p), err)
	} else {
		r.stats.relayOut.Add(1)
		if r.trace {
			log.Printf("TURN_RELAY_OUT local=%s peer=%s bytes=%d", r.LocalAddr(), addr, n)
		}
	}
	return n, err
}

// relayGenerator preserves the upstream generator's allocation behavior while
// observing its returned UDP PacketConns.
type relayGenerator struct {
	turn.RelayAddressGenerator
	stats *counters
	trace bool
}

func (r *relayGenerator) AllocatePacketConn(cfg turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	conn, relayAddr, err := r.RelayAddressGenerator.AllocatePacketConn(cfg)
	if err != nil {
		log.Printf("TURN_RELAY_ALLOCATE_ERROR requested_port=%d error=%v", cfg.RequestedPort, err)
		return nil, nil, err
	}
	log.Printf("TURN_RELAY_SOCKET local=%s advertised=%s", conn.LocalAddr(), relayAddr)
	return &relayLogger{PacketConn: conn, stats: r.stats, trace: r.trace}, relayAddr, nil
}

func logStats(stats *counters, activeAllocations int) {
	log.Printf("TURN_STATS allocations=%d control_in=%d control_out=%d errors=%d channel_in=%d channel_out=%d relay_in=%d relay_out=%d relay_read_errors=%d relay_write_errors=%d",
		activeAllocations,
		stats.controlIn.Load(), stats.controlOut.Load(), stats.controlErrors.Load(),
		stats.channelIn.Load(), stats.channelOut.Load(), stats.relayIn.Load(),
		stats.relayOut.Load(), stats.relayReadErrors.Load(), stats.relayWriteErrors.Load())
}

func diagnosticEvents(traceAuth bool) turn.EventHandler {
	return turn.EventHandler{
		OnAuth: func(src, dst net.Addr, protocol, username, realm, method string, ok bool) {
			if traceAuth || !ok {
				log.Printf("TURN_AUTH src=%s method=%s ok=%t", src, method, ok)
			}
		},
		OnAllocationCreated: func(src, dst net.Addr, protocol, userID, realm string, relay net.Addr, requestedPort int) {
			log.Printf("TURN_ALLOCATION_CREATE client=%s relay=%s requested_port=%d", src, relay, requestedPort)
		},
		OnAllocationDeleted: func(src, dst net.Addr, protocol, userID, realm string) {
			log.Printf("TURN_ALLOCATION_DELETE client=%s", src)
		},
		OnAllocationError: func(src, dst net.Addr, protocol, message string) {
			log.Printf("TURN_ALLOCATION_ERROR client=%s error=%s", src, message)
		},
		OnPermissionCreated: func(src, dst net.Addr, protocol, userID, realm string, relay net.Addr, peer net.IP) {
			log.Printf("TURN_PERMISSION_CREATE client=%s relay=%s peer_ip=%s", src, relay, peer)
		},
		OnPermissionDeleted: func(src, dst net.Addr, protocol, userID, realm string, relay net.Addr, peer net.IP) {
			log.Printf("TURN_PERMISSION_DELETE client=%s relay=%s peer_ip=%s", src, relay, peer)
		},
		OnChannelCreated: func(src, dst net.Addr, protocol, userID, realm string, relay, peer net.Addr, channel uint16) {
			log.Printf("TURN_CHANNEL_CREATE client=%s relay=%s peer=%s channel=%d", src, relay, peer, channel)
		},
		OnChannelDeleted: func(src, dst net.Addr, protocol, userID, realm string, relay, peer net.Addr, channel uint16) {
			log.Printf("TURN_CHANNEL_DELETE client=%s relay=%s peer=%s channel=%d", src, relay, peer, channel)
		},
	}
}

func main() {
	publicIP := flag.String("public-ip", "", "IP Address that TURN can be contacted by.")
	port := flag.Int("port", 3478, "Listening port.")
	users := flag.String("users", "", "List of username and password (e.g. \"user=pass,user=pass\")")
	realm := flag.String("realm", "pion.ly", "Realm (defaults to \"pion.ly\")")
	traceControl := flag.Bool("trace-control", false, "Log every STUN/ChannelData packet's metadata (never payloads).")
	traceRelay := flag.Bool("trace-relay", false, "Log every incoming and outgoing relay UDP packet's metadata.")
	turnDebug := flag.Bool("turn-debug", false, "Enable Pion internal debug logging, including permission/drop details.")
	statsInterval := flag.Duration("stats-interval", 30*time.Second, "Periodic traffic summary; 0 disables summaries.")
	flag.Parse()

	if *statsInterval < 0 {
		log.Fatal("'stats-interval' cannot be negative")
	}
	if net.ParseIP(*publicIP) == nil {
		log.Fatal("'public-ip' must be a valid IP address")
	}
	if len(*users) == 0 {
		log.Fatal("'users' is required")
	}

	// Create a UDP listener to pass into pion/turn
	// pion/turn itself doesn't allocate any UDP sockets, but lets the user pass them in
	// this allows us to add logging, storage or modify inbound/outbound traffic
	udpListener, err := net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(*port))) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to create TURN server listener: %s", err)
	}

	// Cache -users flag for easy lookup later
	// If passwords are stored they should be saved to your DB hashed using turn.GenerateAuthKey
	usersMap := map[string][]byte{}
	for userPass := range strings.SplitSeq(*users, ",") {
		parts := strings.SplitN(userPass, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid user credential format '%s': expected 'username=password'", userPass)
		}
		usersMap[parts[0]] = turn.GenerateAuthKey(parts[0], *realm, parts[1])
	}

	stats := &counters{}
	loggerFactory := logging.NewDefaultLoggerFactory()
	if *turnDebug {
		loggerFactory.DefaultLogLevel = logging.LogLevelDebug
	}
	relay := &relayGenerator{
		RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
			RelayAddress: net.ParseIP(*publicIP),
			Address: "0.0.0.0",
		},
		stats: stats,
		trace: *traceRelay,
	}

	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		LoggerFactory: loggerFactory,
		EventHandler: diagnosticEvents(*traceControl),
		// Set AuthHandler callback
		// This is called every time a user tries to authenticate with the TURN server
		// Return the key for that user, or false when no user is found
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if key, ok := usersMap[ra.Username]; ok {
				return ra.Username, key, true
			}

			return "", nil, false
		},
		// PacketConnConfigs is a list of UDP Listeners and the configuration around them
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: &stunLogger{PacketConn: udpListener, stats: stats, trace: *traceControl},
				RelayAddressGenerator: relay,
			},
		},
	})
	if err != nil {
		log.Panic(err)
	}

	log.Printf("TURN_READY listening=%s public_ip=%s trace_control=%t trace_relay=%t turn_debug=%t",
		udpListener.LocalAddr(), *publicIP, *traceControl, *traceRelay, *turnDebug)

	// Emit low-volume summaries even when packet tracing is disabled.
	var ticks <-chan time.Time
	if *statsInterval > 0 {
		ticker := time.NewTicker(*statsInterval)
		defer ticker.Stop()
		ticks = ticker.C
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-ticks:
			logStats(stats, server.AllocationCount())
		case <-sigs:
			logStats(stats, server.AllocationCount())
			if err = server.Close(); err != nil {
				log.Panic(err)
			}
			return
		}
	}
}
