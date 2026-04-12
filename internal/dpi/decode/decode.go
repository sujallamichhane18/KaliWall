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
	decoded := &types.DecodedPacket{
		Timestamp: time.Now(),
	}
	if ethLayer != nil {
		eth, ok := ethLayer.(*layers.Ethernet)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.SrcMAC = eth.SrcMAC.String()
		decoded.DstMAC = eth.DstMAC.String()
	}

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil {
		ip4, ok := ip4Layer.(*layers.IPv4)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.IPVersion = 4
		decoded.Tuple = types.FiveTuple{
			SrcIP:    ip4.SrcIP.String(),
			DstIP:    ip4.DstIP.String(),
			Protocol: strings.ToLower(ip4.Protocol.String()),
		}
		decoded.NetworkFlow = ip4.NetworkFlow()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, ok := ip6Layer.(*layers.IPv6)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.IPVersion = 6
		decoded.Tuple = types.FiveTuple{
			SrcIP:    ip6.SrcIP.String(),
			DstIP:    ip6.DstIP.String(),
			Protocol: strings.ToLower(ip6.NextHeader.String()),
		}
		decoded.NetworkFlow = ip6.NetworkFlow()
	} else {
		return nil, types.ErrUnsupportedPacket
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

	if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp4, ok := icmp4Layer.(*layers.ICMPv4)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.Tuple.Protocol = "icmp"
		if len(icmp4.Payload) > 0 {
			decoded.Payload = append([]byte(nil), icmp4.Payload...)
		}
		return decoded, nil
	}

	if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, ok := icmp6Layer.(*layers.ICMPv6)
		if !ok {
			return nil, types.ErrMalformedPacket
		}
		decoded.Tuple.Protocol = "icmpv6"
		if len(icmp6.Payload) > 0 {
			decoded.Payload = append([]byte(nil), icmp6.Payload...)
		}
		return decoded, nil
	}

	return nil, fmt.Errorf("%w: %s", types.ErrUnsupportedPacket, decoded.Tuple.Protocol)
}
