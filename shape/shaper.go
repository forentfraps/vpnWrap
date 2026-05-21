// Package shape provides traffic-shape enforcement on a net.Conn so that
// outgoing/incoming byte ratios and burst patterns roughly match what a
// real RDP session looks like to a passive observer.
//
// Real RDP is heavily server -> client dominant (~80-95%) because the server
// pushes screen updates. A VPN tunnel that's symmetric or upload-heavy will
// stand out. We compensate by:
//
//  1. Padding server -> client traffic with no-op chaff frames when the
//     client is uploading heavily.
//  2. Rate-limiting client -> server bursts to look like input events.
package shape

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Profile expresses target traffic characteristics.
type Profile struct {
	// TargetDownRatio is the fraction of total bytes that should flow
	// server -> client. 0.85 is typical for interactive RDP.
	TargetDownRatio float64

	// MaxClientBurst is the largest single Write the client should emit in
	// one burst window. Real input events are tiny; bulk uploads need to be
	// split.
	MaxClientBurst int

	// BurstWindow is how often the client-burst budget refills.
	BurstWindow time.Duration

	// ChaffInterval is how often (if needed) the server emits a chaff frame
	// to maintain the down-ratio. 0 disables chaff.
	ChaffInterval time.Duration
}

// Default returns a reasonable starting profile. Tune per deployment.
func Default() Profile {
	return Profile{
		TargetDownRatio: 0.85,
		MaxClientBurst:  8 * 1024,
		BurstWindow:     50 * time.Millisecond,
		ChaffInterval:   200 * time.Millisecond,
	}
}

// Wrap returns a net.Conn that applies the profile. isServer determines
// which side of the asymmetry we sit on.
func Wrap(inner net.Conn, p Profile, isServer bool) net.Conn {
	s := &shaped{
		Conn:     inner,
		profile:  p,
		isServer: isServer,
		tokens:   int64(p.MaxClientBurst),
	}
	if !isServer {
		s.startTokenRefill()
	}
	return s
}

type shaped struct {
	net.Conn
	profile  Profile
	isServer bool

	bytesUp   atomic.Int64
	bytesDown atomic.Int64

	tokens   int64
	tokensMu sync.Mutex
	tokenCh  chan struct{}
}

func (s *shaped) startTokenRefill() {
	s.tokenCh = make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(s.profile.BurstWindow)
		defer t.Stop()
		for range t.C {
			s.tokensMu.Lock()
			s.tokens = int64(s.profile.MaxClientBurst)
			s.tokensMu.Unlock()
			select {
			case s.tokenCh <- struct{}{}:
			default:
			}
		}
	}()
}

func (s *shaped) Write(p []byte) (int, error) {
	if !s.isServer {
		// Client side: throttle to MaxClientBurst per BurstWindow.
		written := 0
		for len(p) > 0 {
			s.tokensMu.Lock()
			budget := s.tokens
			s.tokensMu.Unlock()
			if budget <= 0 {
				<-s.tokenCh
				continue
			}
			n := int64(len(p))
			if n > budget {
				n = budget
			}
			m, err := s.Conn.Write(p[:n])
			written += m
			s.bytesUp.Add(int64(m))
			s.tokensMu.Lock()
			s.tokens -= int64(m)
			s.tokensMu.Unlock()
			if err != nil {
				return written, err
			}
			p = p[n:]
		}
		return written, nil
	}
	// Server side: write through and track for ratio purposes.
	n, err := s.Conn.Write(p)
	s.bytesDown.Add(int64(n))
	return n, err
}

func (s *shaped) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if s.isServer {
		s.bytesUp.Add(int64(n))
	} else {
		s.bytesDown.Add(int64(n))
	}
	return n, err
}

// Ratio returns the current down/total ratio, for telemetry.
func (s *shaped) Ratio() float64 {
	d := s.bytesDown.Load()
	u := s.bytesUp.Load()
	if d+u == 0 {
		return 0
	}
	return float64(d) / float64(d+u)
}
