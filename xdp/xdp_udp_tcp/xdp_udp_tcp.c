//go:build ignore

#include "../../headers/common.h"
#include <linux/in.h>
#include <linux/tcp.h>
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

// 提取公共的处理逻辑，避免重复代码
static inline void process_packet(struct iphdr *iph, void *data, void *data_end,
                                  struct event *e) {
  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = data + sizeof(*iph);
    if (data + sizeof(*iph) + sizeof(*udph) > data_end)
      return;
    e->saddr = iph->saddr;
    e->daddr = iph->daddr;
    e->sport = bpf_ntohs(udph->source);
    e->dport = bpf_ntohs(udph->dest);
  } else if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = data + sizeof(*iph);
    if (data + sizeof(*iph) + sizeof(*tcph) > data_end)
      return;
    e->saddr = iph->saddr;
    e->daddr = iph->daddr;
    e->sport = bpf_ntohs(tcph->source);
    e->dport = bpf_ntohs(tcph->dest);
  }
}

// XDP 处理函数
SEC("xdp") int xdp_udp_tcp(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  // 检查数据包是否足够长以包含以太网头部
  if (data + sizeof(*eth) > data_end)
    return XDP_PASS;

  // 确保是 IP 协议
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  // 获取 IP 头部
  struct iphdr *iph = data + sizeof(*eth);
  if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    return XDP_PASS;

  // 只处理 UDP 或 TCP 协议
  if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP)
    return XDP_PASS;

  // 预留空间以填充事件数据
  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  // 处理数据包内容
  process_packet(iph, data + sizeof(*eth), data_end, e);

  // 提交事件
  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
