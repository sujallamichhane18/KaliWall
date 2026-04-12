package lite

import (
	"testing"

	"kaliwall/internal/dpi/types"
)

func TestRecordEnforcesMaliciousIndicators(t *testing.T) {
	var blockedIPs []string
	var blockedDomains []string

	e := New(Config{
		MaliciousIPMatcher: func(ip string) bool {
			return ip == "1.2.3.4"
		},
		MaliciousDomainMatcher: func(domain string) bool {
			return domain == "bad.example"
		},
		IsIPBlocked: func(string) bool { return false },
		IsWebsiteBlocked: func(string) bool { return false },
		BlockIP: func(ip, _ string) error {
			blockedIPs = append(blockedIPs, ip)
			return nil
		},
		BlockWebsite: func(domain, _ string) error {
			blockedDomains = append(blockedDomains, domain)
			return nil
		},
	}, nil)

	e.record(types.InspectResult{
		Tuple: types.FiveTuple{
			SrcIP: "1.2.3.4",
			DstIP: "8.8.8.8",
		},
		DNSDomain: "bad.example",
		TLSSNI:    "bad.example",
		HTTPHost:  "bad.example:443",
	})

	if len(blockedIPs) != 1 || blockedIPs[0] != "1.2.3.4" {
		t.Fatalf("expected one blocked IP 1.2.3.4, got %#v", blockedIPs)
	}
	if len(blockedDomains) != 1 || blockedDomains[0] != "bad.example" {
		t.Fatalf("expected one blocked domain bad.example, got %#v", blockedDomains)
	}
}

func TestRecordSkipsAlreadyBlockedIndicators(t *testing.T) {
	ipBlockCalls := 0
	domainBlockCalls := 0

	e := New(Config{
		MaliciousIPMatcher:     func(string) bool { return true },
		MaliciousDomainMatcher: func(string) bool { return true },
		IsIPBlocked:            func(string) bool { return true },
		IsWebsiteBlocked:       func(string) bool { return true },
		BlockIP: func(string, string) error {
			ipBlockCalls++
			return nil
		},
		BlockWebsite: func(string, string) error {
			domainBlockCalls++
			return nil
		},
	}, nil)

	e.record(types.InspectResult{
		Tuple: types.FiveTuple{
			SrcIP: "5.6.7.8",
			DstIP: "8.8.8.8",
		},
		DNSDomain: "evil.example",
	})

	if ipBlockCalls != 0 {
		t.Fatalf("expected no IP block calls, got %d", ipBlockCalls)
	}
	if domainBlockCalls != 0 {
		t.Fatalf("expected no domain block calls, got %d", domainBlockCalls)
	}
}

func TestNormalizeIndicatorDomain(t *testing.T) {
	got := normalizeIndicatorDomain("https://api.bad.example:443/path?q=1")
	if got != "api.bad.example" {
		t.Fatalf("expected api.bad.example, got %q", got)
	}
}
