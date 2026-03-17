package capture

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Capturer abstracts packet source implementation.
type Capturer interface {
	Start(ctx context.Context) error
	Packets() <-chan gopacket.Packet
	Errors() <-chan error
	Close() error
}

// Config controls packet capture behavior.
type Config struct {
	Interface   string
	Promiscuous bool
	SnapLen     int32
	Timeout     time.Duration
	BPF         string
}

// PcapCapturer reads packets from live interface using pcap.
type PcapCapturer struct {
	cfg     Config
	handle  *pcap.Handle
	packets chan gopacket.Packet
	errs    chan error
	closed  chan struct{}
}

func New(cfg Config) *PcapCapturer {
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65535
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	return &PcapCapturer{
		cfg:     cfg,
		packets: make(chan gopacket.Packet, 2048),
		errs:    make(chan error, 64),
		closed:  make(chan struct{}),
	}
}

func (c *PcapCapturer) Start(ctx context.Context) error {
	h, err := pcap.OpenLive(c.cfg.Interface, c.cfg.SnapLen, c.cfg.Promiscuous, c.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("pcap open failed: %w", err)
	}
	c.handle = h
	if c.cfg.BPF != "" {
		if err := c.handle.SetBPFFilter(c.cfg.BPF); err != nil {
			c.handle.Close()
			return fmt.Errorf("bpf filter failed: %w", err)
		}
	}

	go func() {
		defer close(c.packets)
		defer close(c.errs)
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			default:
			}

			data, ci, err := c.handle.ReadPacketData()
			if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					continue
				}
				select {
				case c.errs <- err:
				default:
				}
				continue
			}
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: false})
			pkt.Metadata().CaptureInfo = ci
			select {
			case c.packets <- pkt:
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			}
		}
	}()

	return nil
}

func (c *PcapCapturer) Packets() <-chan gopacket.Packet { return c.packets }

func (c *PcapCapturer) Errors() <-chan error { return c.errs }

func (c *PcapCapturer) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	if c.handle != nil {
		c.handle.Close()
	}
	return nil
}
