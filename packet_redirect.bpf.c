#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "xx_hash.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define TC_ACT_OK 0
#define TC_ACT_REDIRECT 7

// the interface we will redirect to.
#define TARGET_INTF 4
// the destination IP that determines if we will redirect the packet.
#define DEST_IP 0x0a00020b  // 10.0.2.11

// look for an IPv4 packet with destination address 10.0.2.11 and redirect
// it to a target interface.
SEC("tc")
int egress_redirect(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)(ctx->data_end);
    void *data = (void *)(__u64)(ctx->data);
    struct ethhdr *eth;
    struct iphdr *ipv4;
    int ret = TC_ACT_OK;

    bpf_printk("redirect: handling a packet\n");

    // bounds check for verifier, packet's data must be at least as large
    // as an ethernet header and the non-variable portion of the IPv4 header.
    if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end))
        goto END;

    eth = data;
    ipv4 = data + sizeof(struct ethhdr);

    bpf_printk("redirect: checking ethernet header for IPv4 proto. result: %x\n", bpf_ntohs(eth->h_proto));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    bpf_printk("redirect: checking destination address is 10.0.2.11\n");
    if (bpf_ntohl(ipv4->daddr) != DEST_IP) return TC_ACT_OK;

    //bpf_printk("redirect: rewriting destination MAC\n");
    //eth->h_dest[0] = 0x02;
    //eth->h_dest[1] = 0x00;
    //eth->h_dest[2] = 0x00;
    //eth->h_dest[3] = 0x00;
    //eth->h_dest[4] = 0x00;
    //eth->h_dest[5] = 0x00;

    struct {
        __u32 src_ip;
        __u32 dst_ip;
    } flow_key = {bpf_ntohs(ipv4->saddr), bpf_ntohs(ipv4->daddr)};

    __u32 hash = xxhash32(&flow_key, sizeof(flow_key), 0);
    __u32 key = hash % 2;
    bpf_printk("redirect: hash: %d\n", hash);
    bpf_printk("redirect: key: %d\n", key);
    if (key != 0) { 
        bpf_printk("redirect: performing redirect\n");
        ret = bpf_redirect(TARGET_INTF, 0);
    } else {
        bpf_printk("redirect: NOT performing redirect\n");
    }

    bpf_printk("redirect: result: %d\n", ret);
END:
    bpf_printk("---------------<END>---------------\n\n\n");
    return ret;
}

char _license[] SEC("license") = "GPL";
