package decode

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestDecodeTCPPacket(t *testing.T) {
	d := New()
	payload := []byte("GET /login HTTP/1.1\r\nHost: test\r\n\r\n")
	pkt := buildTCPPacket(t, payload)

	decoded, err := d.Decode(pkt)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Tuple.Protocol != "tcp" {
		t.Fatalf("expected tcp protocol, got %s", decoded.Tuple.Protocol)
	}
	if decoded.Tuple.SrcIP != "10.10.10.2" || decoded.Tuple.DstIP != "10.10.10.1" {
		t.Fatalf("unexpected tuple src/dst: %s -> %s", decoded.Tuple.SrcIP, decoded.Tuple.DstIP)
	}
	if string(decoded.Payload) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestDecodeUDPDNSPacket(t *testing.T) {
	d := New()
	pkt := buildDNSPacket(t, "api.bad.com")

	decoded, err := d.Decode(pkt)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Tuple.Protocol != "udp" {
		t.Fatalf("expected udp protocol, got %s", decoded.Tuple.Protocol)
	}
	if decoded.DNSQuery != "api.bad.com" {
		t.Fatalf("expected DNS query api.bad.com, got %s", decoded.DNSQuery)
	}
}

func buildTCPPacket(t *testing.T, appPayload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("10.10.10.2").To4(),
		DstIP:    net.ParseIP("10.10.10.1").To4(),
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 8080,
		Seq:     1,
		Ack:     1,
		PSH:     true,
		ACK:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set checksum layer failed: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(appPayload)); err != nil {
		t.Fatalf("serialize tcp packet failed: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func buildDNSPacket(t *testing.T, q string) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.10.10.2").To4(),
		DstIP:    net.ParseIP("8.8.8.8").To4(),
	}
	udp := &layers.UDP{
		SrcPort: 53530,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set udp checksum layer failed: %v", err)
	}
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           false,
		OpCode:       layers.DNSOpCodeQuery,
		RD:           true,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(q),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		t.Fatalf("serialize dns packet failed: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}
