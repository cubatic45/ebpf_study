//go:build ignore

#include "../../headers/common.h"
#include "dns.h"
#include <linux/in.h>
#include <linux/udp.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct event {
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u16 id;
  __u16 qtype;
  __u16 qclass;
  char qname[256];
};
struct event *unused_event __attribute__((unused));

static __always_inline int parse_dns_header(void *data, void *data_end,
                                            struct dns_header *header) {

  if ((void *)data + sizeof(*header) > data_end) {
    return -1;
  }
  __u8 *cursor = (__u8 *)data;

  header->id = bpf_ntohs(*(__u16 *)(cursor));
  __u16 flags = bpf_ntohs(*(__u16 *)(cursor + 2));
  header->flags = *(struct dns_flags *)&flags;
  header->qdcount = bpf_ntohs(*(__u16 *)(cursor + 4));
  header->ancount = bpf_ntohs(*(__u16 *)(cursor + 6));
  header->nscount = bpf_ntohs(*(__u16 *)(cursor + 8));
  header->arcount = bpf_ntohs(*(__u16 *)(cursor + 10));
#ifdef BPF_DEBUG
  bpf_printk("[dns header] DNS query id:%x, qr:%d, opcode:%d\n", header->id,
             header->flags.qr, header->flags.opcode);
#endif

  return 0;
}

static __always_inline int parse_dns_question(void *data, void *data_end,
                                              struct dns_question *question) {
  __u8 *cursor = (__u8 *)data;
  __u8 *end = (__u8 *)data_end;

  question->qtype = 0;
  question->qclass = 0;
//__builtin_memcpy(query->qname, 0, sizeof(query->qname));
#pragma unroll
  for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
    question->qname[i] = 0;
  }

  int label_len = 0;

  for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
    if (cursor + 1 > end) {
      return -1;
    }

    label_len = *cursor;

    if (label_len == 0) {
      if (cursor + 5 > end) {
        return -1; // Ensure there's enough space for qtype and qclass
      }
      question->qname[i] = *cursor++;
      question->qtype = bpf_ntohs(*(__u16 *)cursor);
      cursor += 2;
      question->qclass = bpf_ntohs(*(__u16 *)(cursor));
      return i + 1;
    }

    if (i + 1 > MAX_DOMAIN_LEN) {
      return -1;
    }

    question->qname[i] = *cursor;
    cursor++;
  }

  return -1;
}

SEC("xdp") int xdp_udp_dns(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)eth + sizeof(*eth) > data_end) {
    return XDP_PASS;
  }
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *iph = (void *)eth + sizeof(*eth);
  if ((void *)iph + sizeof(*iph) > data_end) {
    return XDP_PASS;
  }
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  struct udphdr *udph = (void *)iph + sizeof(*iph);
  if ((void *)udph + sizeof(*udph) > data_end)
    return XDP_PASS;
  if (udph->dest != bpf_htons(53))
    return XDP_PASS;

  struct dns_header dns_h;
  struct dns_flags *dns_f = &dns_h.flags;
  void *dns_payload = (void *)udph + sizeof(*udph);
  if (parse_dns_header(dns_payload, data_end, &dns_h) < 0) {
    bpf_printk("parse dns header failed\n");
    return XDP_PASS;
  }

  // check this message is a query (0), response (1).
  if (dns_f->qr != 0) {
    return XDP_PASS;
  }

  // standard query opcode should be 0
  if (dns_f->opcode != 0) {
    return XDP_PASS;
  }

  struct dns_question dns_q;
  void *question_payload = dns_payload + sizeof(dns_h);
  int qname_len = parse_dns_question(question_payload, data_end, &dns_q);
  if (qname_len < 0) {
    bpf_printk("parse dns question failed\n");
    return XDP_PASS;
  }
#ifdef BPF_DEBUG
  bpf_printk("dns query id:%x, qname:%s, qtype:%d, qclass:%d, qname_len:%d\n",
             dns_h.id, dns_q.qname, dns_q.qtype, dns_q.qclass, qname_len);
#endif
  if (dns_q.qtype != QTYPE_A && dns_q.qtype != QTYPE_AAAA) {
    return XDP_PASS;
  }
  if (dns_q.qclass != QCLASS_IN) {
    return XDP_PASS;
  }

  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->saddr = iph->saddr;
  e->daddr = iph->daddr;
  e->sport = bpf_ntohs(udph->source);
  e->dport = bpf_ntohs(udph->dest);
  e->id = dns_h.id;
  __builtin_memcpy(e->qname, dns_q.qname, sizeof(e->qname));
  e->qtype = dns_q.qtype;
  e->qclass = dns_q.qclass;
  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
