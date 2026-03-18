package decode

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"kaliwall/internal/dpi/types"
)

// Decoder converts raw gopacket packets into normalized decoded records.
type Decoder interface {
	Decode(packet gopacket.Packet) (*types.DecodedPacket, error)
}

// GopacketDecoder reads Ethernet/IPv4/TCP/UDP/DNS layers.
type GopacketDecoder struct{}

func New() *GopacketDecoder { return &GopacketDecoder{} }

func (d *GopacketDecoder) Decode(packet gopacket.Packet) (*types.DecodedPacket, error) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, types.ErrUnsupportedPacket
	}
	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok {
		return nil, types.ErrMalformedPacket
	}

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return nil, types.ErrUnsupportedPacket
	}
	ip4, ok := ip4Layer.(*layers.IPv4)
	if !ok {
		return nil, types.ErrMalformedPacket
	}

	decoded := &types.DecodedPacket{
		Timestamp: time.Now(),
		Tuple: types.FiveTuple{
			SrcIP:    ip4.SrcIP.String(),
			DstIP:    ip4.DstIP.String(),
			Protocol: strings.ToLower(ip4.Protocol.String()),
		},
		SrcMAC:      eth.SrcMAC.String(),
		DstMAC:      eth.DstMAC.String(),
		NetworkFlow: ip4.NetworkFlow(),
	}
	if md := packet.Metadata(); md != nil && !md.Timestamp.IsZero() {
		decoded.Timestamp = md.Timestamp
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		tcpCopy := *tcp
		decoded.Tuple.Protocol = "tcp"
		decoded.Tuple.SrcPort = uint16(tcp.SrcPort)
		decoded.Tuple.DstPort = uint16(tcp.DstPort)
		decoded.TransportFlow = tcp.TransportFlow()
		decoded.TCPSegment = &tcpCopy
		decoded.TCPSeq = tcp.Seq
		decoded.TCPAck = tcp.Ack
		if len(tcp.Payload) > 0 {
			decoded.Payload = append([]byte(nil), tcp.Payload...)
		}
		return decoded, nil
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.Tuple.Protocol = "udp"
		decoded.Tuple.SrcPort = uint16(udp.SrcPort)
		decoded.Tuple.DstPort = uint16(udp.DstPort)
		decoded.TransportFlow = udp.TransportFlow()
		if len(udp.Payload) > 0 {
			decoded.Payload = append([]byte(nil), udp.Payload...)
		}

		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, ok := dnsLayer.(*layers.DNS)
			if !ok {
				return nil, types.ErrMalformedPacket
			}
			if len(dns.Questions) > 0 {
				decoded.DNSQuery = strings.ToLower(string(dns.Questions[0].Name))
			}
		}
		return decoded, nil
	}

	return nil, fmt.Errorf("%w: %s", types.ErrUnsupportedPacket, ip4.Protocol.String())
}
