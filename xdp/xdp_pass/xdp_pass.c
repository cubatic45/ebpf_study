//go:build ignore

#include "../../headers/common.h"

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
  bpf_printk("XDP_PASS\n");
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
