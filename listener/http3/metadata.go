package http3

import (
	"fmt"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/quic/congestion/bbr"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128

	ccBBR    = "bbr"
	ccBrutal = "brutal"
)

type metadata struct {
	backlog int

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
	enableDatagrams  bool

	// Congestion control of the sending (server to client) direction:
	// "" keeps the quic-go default, "bbr" or "brutal" replace it.
	cc                        string
	ccBBRProfile              string
	ccUp                      uint64 // brutal send rate, bytes per second
	ccDisableLossCompensation bool
}

func (l *http3Listener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"

		backlog = "backlog"
	)

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if mdutil.GetBool(md, keepAlive) {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	l.md.maxStreams = mdutil.GetInt(md, maxStreams)
	if mdutil.IsExists(md, "enableDatagrams") {
		l.md.enableDatagrams = mdutil.GetBool(md, "enableDatagrams")
	} else {
		l.md.enableDatagrams = true
	}

	switch cc := strings.ToLower(mdutil.GetString(md, "cc", "congestion")); cc {
	case "", "reno", "cubic":
	case ccBBR:
		l.md.cc = cc
		profile, err := bbr.ParseProfile(mdutil.GetString(md, "cc.bbrProfile"))
		if err != nil {
			return err
		}
		l.md.ccBBRProfile = string(profile)
	case ccBrutal:
		l.md.cc = cc
		// Brutal sends at a fixed rate and needs it set: unlike Hysteria,
		// MASQUE clients do not announce their receive bandwidth.
		mbps := mdutil.GetFloat(md, "cc.up")
		if mbps <= 0 {
			return fmt.Errorf("cc=brutal needs cc.up, the send rate in Mbps")
		}
		l.md.ccUp = uint64(mbps * 1000 * 1000 / 8)
		l.md.ccDisableLossCompensation = mdutil.GetBool(md, "cc.disableLossCompensation")
	default:
		return fmt.Errorf("unknown cc %q, want bbr or brutal", cc)
	}

	return
}
