#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <base.h>
#include <net-config.h>

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
				   struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct rte_ether_hdr *hdr =
		rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

	hdr->dst_addr = *dst_haddr;
	memcpy(&hdr->src_addr, local_mac, 6);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
	pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
	pkt_buf->pkt_len = pkt_buf->data_len;
	dpdk_out(pkt_buf);

	return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
	arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* fill arp body */
	arph->arp_data.arp_tip = arph->arp_data.arp_sip;
	arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

	arph->arp_data.arp_tha = arph->arp_data.arp_sha;
	memcpy(&arph->arp_data.arp_sha, local_mac, 6);

	eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
			sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
	struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
		pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
		goto OUT;

	switch (rte_be_to_cpu_16(arph->arp_opcode)) {
	case RTE_ARP_OP_REQUEST:
		arp_reply(pkt, arph);
		break;
	default:
		fprintf(stderr, "apr: Received unknown ARP op");
		goto OUT;
	}

	return;

OUT:
	rte_pktmbuf_free(pkt);
	return;
}

static struct rte_ether_addr *get_mac_for_ip(uint32_t ip)
{
	return &mac_addresses[(ip & 0xf) - 1];
}

static uint32_t get_target_ip(uint32_t src_ip, uint16_t src_port,
							  uint16_t dst_port)
{
	/* FIXME: Implement the load balancing policy here */
	/* If src_ip is 10.0.0.2 or 10.0.0.3 then target_ip is 10.0.0.1*/
	/* If src_ip is 10.0.0.10, then perform hash of src_ip, src_port, dst_port since these
		are the only three fields which change.Then use hash to choose target ip from targets array*/

	if (src_ip == targets[0] || src_ip == targets[1]){
		return 0xa000001;
	} else {
		int hash_val = (src_ip + src_port + dst_port) % target_count;
		return targets[hash_val];
	}
}

static void lb_in(struct rte_mbuf *pkt_buf)
{
	struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(
		pkt_buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	struct rte_tcp_hdr *tcph = rte_pktmbuf_mtod_offset(
		pkt_buf, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));


	/* FIXME: Use the get_target_ip function to get the target server IP */
	uint32_t target_ip = get_target_ip(ntohl(iph->src_addr), ntohs(rte_be_to_cpu_16(tcph->src_port)), ntohs(rte_be_to_cpu_16(tcph->dst_port)));
	/* FIXME: Set the src and destination IPs */
	iph->src_addr = htonl(local_ip);
    iph->dst_addr = htonl(target_ip);

	/* FIXME: Fix the tcp and ip checksums */
    tcph->cksum = 0;
    tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = calculate_ipv4_checksum(iph);

	/* Send the packet out */
    eth_out(pkt_buf, RTE_ETHER_TYPE_IPV4, get_mac_for_ip(target_ip), sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));

}

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

	if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_in(pkt_buf);
	} else if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		lb_in(pkt_buf);
	} else {
		// printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}
