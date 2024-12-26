package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ./xdp_udp_dns.c -- -I../../headers -DBPF_DEBUG

var ifaceName string

func init() {
	flag.StringVar(&ifaceName, "n", "lo", "network interface name to attach xdp")
	flag.Parse()
	// go dnsServer()
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
		Program:   objs.XdpUdpDns,
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
			printDnsEvent(bpfEvent)
		}
	}()

	select {}
}

func printDnsEvent(bpfEvent bpfEvent) {
	log.Printf("-----------------------------DNS-------------------------------")
	log.Printf("saddr: %s, daddr: %s, sport: %d, dport: %d",
		uint32ToIP(bpfEvent.Saddr), uint32ToIP(bpfEvent.Daddr), bpfEvent.Sport, bpfEvent.Dport)
	log.Printf("id: %d, qname: %s, qtype: %d, qclass: %d",
		bpfEvent.Id, sliceToStr(bpfEvent.Qname[:]), bpfEvent.Qtype, bpfEvent.Qclass)
	_, err := queryDnsOverHttps(sliceToStr(bpfEvent.Qname[:]), bpfEvent.Qtype)
	if err != nil {
		log.Printf("failed to query DNS over HTTPS: %v", err)
		return
	}
}

// \x06google\x03com\x00 -> google.com
func sliceToStr(slice []int8) string {
	var parts []string
	var current bytes.Buffer

	for i := 0; i < len(slice); {
		length := int(slice[i])
		if length == 0 {
			break
		}

		i++
		for j := 0; j < length && i < len(slice); j++ {
			current.WriteByte(byte(slice[i]))
			i++
		}

		parts = append(parts, current.String())
		current.Reset()
	}

	return strings.Join(parts, ".")
}

func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
