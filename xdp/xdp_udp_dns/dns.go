package main

import (
	"encoding/base64"
	"io"
	"log"
	"net/http"

	"github.com/miekg/dns"
)

const (
	DoHServer = "https://cloudflare-dns.com/dns-query"
	QtypeA    = 1
	QtypeAAAA = 28
)

func queryDnsOverHttps(qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)

	packed, err := m.Pack()
	if err != nil {
		log.Printf("pack dns message failed: %v\n", err)
		return nil, err
	}

	b64 := base64.RawURLEncoding.EncodeToString(packed)

	req, err := http.NewRequest("GET", DoHServer+"?dns="+b64, nil)
	if err != nil {
		log.Printf("create request failed: %v\n", err)
		return nil, err
	}

	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("send request failed: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("read response failed: %v\n", err)
		return nil, err
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		log.Printf("unpack dns response failed: %v\n", err)
		return nil, err
	}

	for _, ans := range r.Answer {
		log.Printf("dns response: %v\n", ans)
	}
	return r, nil
}
