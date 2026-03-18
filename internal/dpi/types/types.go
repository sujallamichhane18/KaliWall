package types

import (
	"errors"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Action describes what to do with inspected traffic.
type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionBlock Action = "BLOCK"
	ActionLog   Action = "LOG"
)

var (
	ErrUnsupportedPacket = errors.New("unsupported packet")
	ErrMalformedPacket   = errors.New("malformed packet")
)

// FiveTuple identifies a transport flow.
type FiveTuple struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// DecodedPacket is the normalized output of packet decode stage.
type DecodedPacket struct {
	Timestamp time.Time
	Tuple     FiveTuple
	IPVersion uint8
	SrcMAC    string
	DstMAC    string
	NetworkFlow   gopacket.Flow
	TransportFlow gopacket.Flow
	TCPSegment    *layers.TCP
	TCPSeq    uint32
	TCPAck    uint32
	Payload   []byte
	DNSQuery  string
}

// AppPayload is the output of transport reassembly ready for DPI inspection.
type AppPayload struct {
	Timestamp   time.Time
	Tuple       FiveTuple
	Payload     []byte
	DNSQuery    string
	Reassembled bool
}

// InspectResult contains protocol-aware extracted artifacts and detections.
type InspectResult struct {
	Timestamp      time.Time
	Tuple          FiveTuple
	Protocol       string
	HTTPMethod     string
	HTTPHost       string
	HTTPURL        string
	HTTPHeaders    map[string]string
	DNSDomain      string
	TLSSNI         string
	Payload        []byte
	Detections     []string
	MatchedRuleIDs []string
}
