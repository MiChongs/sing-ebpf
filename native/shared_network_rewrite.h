// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_SHARED_NETWORK_REWRITE_H
#define SING_EBPF_SHARED_NETWORK_REWRITE_H

// A zero UDP checksum means the sender computed none, which IPv4 allows (VXLAN
// and L2TP default to it). BPF_F_MARK_MANGLED_0 leaves it zero and turns an
// updated checksum that folds to zero into CSUM_MANGLED_0, as kernel NAT does.
// BPF_F_MARK_ENFORCE would update the zero as if it were a checksum and the
// receiver would drop the datagram. A real checksum is never zero, not even
// the pseudo-header seed of a CHECKSUM_PARTIAL packet.
INLINE __u64 checksum_flags(__u8 protocol, __u64 size) {
	__u64 flags = size;
	if (protocol == IPPROTO_UDP_VALUE) flags |= BPF_F_MARK_MANGLED_0;
	return flags;
}

INLINE __u64 pseudo_header_checksum_flags(__u8 protocol, __u64 size) {
	return checksum_flags(protocol, size) | BPF_F_PSEUDO_HDR;
}

INLINE int rewrite_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    __be32 old_address,
    __be32 new_address,
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv4_header, source)
        : __builtin_offsetof(struct ipv4_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
	__u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
		? __builtin_offsetof(struct tcp_header_min, checksum)
		: __builtin_offsetof(struct udp_header_min, checksum));
	if (l3_csum_replace(
			skb,
            l3_offset + __builtin_offsetof(struct ipv4_header, checksum),
            old_address,
            new_address,
			4U) != 0) {
		record_rewrite_failure();
		return TC_ACT_SHOT;
	}
	// A 4-byte pseudo-header replacement folds the address change directly;
	// unlike IPv6 it needs no separate csum_diff call.
	if (l4_csum_replace(skb, checksum_offset, old_address, new_address, pseudo_header_checksum_flags(protocol, 4U)) != 0 ||
		l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, &new_address, sizeof(new_address), 0U) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        record_rewrite_failure();
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE int rewrite_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    __u32 l4_offset,
    bool source,
    const __u8 old_address[16],
    const __u8 new_address[16],
    __be16 old_port,
    __be16 new_port,
    __u8 protocol) {
    __u32 checksum_offset = l4_offset + (protocol == IPPROTO_TCP_VALUE
        ? __builtin_offsetof(struct tcp_header_min, checksum)
        : __builtin_offsetof(struct udp_header_min, checksum));
    __s64 address_diff = csum_diff(
        (const __be32 *)old_address,
        16U,
        (const __be32 *)new_address,
        16U,
        0U);
    if (address_diff < 0) { record_rewrite_failure(); return TC_ACT_SHOT; }
    __u32 address_offset = l3_offset + (source
        ? __builtin_offsetof(struct ipv6_header, source)
        : __builtin_offsetof(struct ipv6_header, destination));
    __u32 port_offset = l4_offset + (source ? 0U : 2U);
    // On a CHECKSUM_COMPLETE skb a pseudo-header l4_csum_replace also takes
    // the address diff out of skb->csum, as if an IPv4 header checksum had
    // absorbed the address change. IPv6 has none, so the stored address must
    // put the diff back, or the stack reports "hw csum failure" and verifies
    // every rewritten packet in software. BPF_F_IPV6 says the same thing but
    // only exists since Linux 6.16; the recompute flag only touches COMPLETE.
	if (l4_csum_replace(skb, checksum_offset, 0U, (__u64)address_diff, pseudo_header_checksum_flags(protocol, 0U)) != 0 ||
        l4_csum_replace(skb, checksum_offset, old_port, new_port, checksum_flags(protocol, 2U)) != 0 ||
        skb_store_bytes(skb, address_offset, new_address, 16U, BPF_F_RECOMPUTE_CSUM) != 0 ||
        skb_store_bytes(skb, port_offset, &new_port, sizeof(new_port), 0U) != 0) {
        record_rewrite_failure();
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

INLINE bool ipv4_token_address(__be32 address, const struct sb_shared_control *control) {
    __u32 host = network_order32(address);
    __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
        ((__u32)control->token_ipv4_prefix[1] << 16U) |
        ((__u32)control->token_ipv4_prefix[2] << 8U) |
        (__u32)control->token_ipv4_prefix[3];
    __u32 bits = control->token_ipv4_prefix_bits;
    __u32 mask = bits == 0U ? 0U : 0xffffffffU << (32U - bits);
    return (host & mask) == (prefix & mask);
}

INLINE bool ipv6_token_address(const __u8 address[16], const struct sb_shared_control *control) {
    return equal_address(address, control->token_ipv6_prefix, 8U);
}

#endif
