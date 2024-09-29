//go:build ignore

#include "../../headers/common.h"
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
};
struct event *unused_event __attribute__((unused));

SEC("xdp") int xdp_udp(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph = data + sizeof(*eth);
  struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);

  if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
    return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  bpf_printk("-------------UDP--------------");
  bpf_printk("src_host %d:%d", iph->saddr, bpf_ntohs(udph->source));
  bpf_printk("dst_host %d:%d", iph->daddr, bpf_ntohs(udph->dest));

  struct event *e;
  // 必需步骤 判断是否有足够空间
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->saddr = iph->saddr;
  e->daddr = iph->daddr;
  e->sport = bpf_ntohs(udph->source);
  e->dport = bpf_ntohs(udph->dest);
  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
