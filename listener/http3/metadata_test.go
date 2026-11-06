package http3

import (
	"testing"

	mdx "github.com/go-gost/x/metadata"
)

func TestParseCongestionControl(t *testing.T) {
	tests := []struct {
		name    string
		md      map[string]any
		cc      string
		up      uint64
		profile string
		wantErr bool
	}{
		{name: "default keeps quic-go", md: map[string]any{}},
		{name: "reno keeps quic-go", md: map[string]any{"cc": "reno"}},
		{name: "brutal", md: map[string]any{"cc": "brutal", "cc.up": "100"}, cc: ccBrutal, up: 12_500_000},
		{name: "brutal fractional mbps", md: map[string]any{"cc": "Brutal", "cc.up": 0.5}, cc: ccBrutal, up: 62_500},
		{name: "brutal without rate", md: map[string]any{"cc": "brutal"}, wantErr: true},
		{name: "bbr default profile", md: map[string]any{"cc": "bbr"}, cc: ccBBR, profile: "standard"},
		{name: "bbr aggressive", md: map[string]any{"congestion": "bbr", "cc.bbrProfile": "aggressive"}, cc: ccBBR, profile: "aggressive"},
		{name: "bbr bad profile", md: map[string]any{"cc": "bbr", "cc.bbrProfile": "turbo"}, wantErr: true},
		{name: "unknown", md: map[string]any{"cc": "vegas"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &http3Listener{}
			err := l.parseMetadata(mdx.NewMetadata(tt.md))
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if l.md.cc != tt.cc || l.md.ccUp != tt.up || l.md.ccBBRProfile != tt.profile {
				t.Fatalf("got cc=%q up=%d profile=%q", l.md.cc, l.md.ccUp, l.md.ccBBRProfile)
			}
		})
	}
}
