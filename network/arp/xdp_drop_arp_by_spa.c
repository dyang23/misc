// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * key = 0
 * value = IPv4 address in network byte order
 *
 * Example:
 *   10.0.0.2 -> 0x0a000002
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_spa_map SEC(".maps");

SEC("xdp")
int xdp_drop_arp_by_spa(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* L2: Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_ARP)) {
        return XDP_PASS;
    }

    /*
     * ARP on Ethernet/IPv4 layout:
     *   struct arphdr
     *   sha[6]
     *   spa[4]
     *   tha[6]
     *   tpa[4]
     */
    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end) {
        return XDP_PASS;
    }

    if (arp->ar_op != bpf_htons(ARPOP_REQUEST)) {
        return XDP_PASS;
    }

    /* Optional but recommended: ensure Ethernet + IPv4 ARP */
    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
        arp->ar_pro != bpf_htons(ETH_P_IP)    ||
        arp->ar_hln != ETH_ALEN               ||
        arp->ar_pln != 4) {
        return XDP_PASS;
    }

    unsigned char *arp_ptr = (unsigned char *)(arp + 1);

    /* Need at least sha(6) + spa(4) bytes */
    if ((void *)(arp_ptr + ETH_ALEN + 4) > data_end) {
        return XDP_PASS;
    }

    /* Skip sha[6], then read spa[4] */
    __u32 spa = *(__u32 *)(arp_ptr + ETH_ALEN);

    __u32 key = 0;
    __u32 *blocked_spa = bpf_map_lookup_elem(&blocked_spa_map, &key);
    if (!blocked_spa) {
        return XDP_PASS;
    }

    if (spa == *blocked_spa) {
        bpf_printk("Drop ARP request from SPA=%x\n", bpf_ntohl(spa));
        return XDP_DROP;
    }

    return XDP_PASS;
}
