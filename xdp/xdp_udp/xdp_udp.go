package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ./xdp_udp.c -- -I../../headers

var ifaceName string

func init() {
	flag.StringVar(&ifaceName, "n", "lo", "network interface name to attach xdp")
	flag.Parse()
}

func main() {
	// Look up the network interface by name.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}
	log.Printf("Successfully attach to interface: %s\n", ifaceName)

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpUdp,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Successfully started! Please run \"sudo cat /sys/kernel/debug/tracing/trace_pipe\" to see output of the BPF programs\n")

	rinbufReader, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rinbufReader.Close()
	go func() {
		for {
			event, err := rinbufReader.Read()
			if err != nil {
				log.Fatalf("failed to read ringbuf: %v", err)
			}
			bpfEvent := bpfEvent{}
			binary.Read(bytes.NewReader(event.RawSample), binary.LittleEndian, &bpfEvent)
			log.Printf("saddr: %s, daddr: %s, sport: %d, dport: %d\n",
				uint32ToIP(bpfEvent.Saddr), uint32ToIP(bpfEvent.Daddr), bpfEvent.Sport, bpfEvent.Dport)
		}
	}()

	select {}
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
