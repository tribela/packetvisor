#include "internal_offload.h"

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <pv/nic.h>
#include <pv/packet.h>
#include <pv/net/vlan.h>
#include <pv/net/ipv4.h>
#include <pv/checksum.h>
#include <pv/offload.h>

void vlan_strip(const struct pv_nic* nic, struct pv_packet* const packet, uint16_t const ethtype, struct pv_vlan_info* info);
void vlan_insert(const struct pv_nic* nic, struct pv_packet* const packet, uint16_t ethtype, struct pv_vlan_info* info);

void rx_offload_vlan_strip(const struct pv_nic* nic, struct pv_packet* const packet) {
    struct pv_vlan_info info;
    vlan_strip(nic, packet, PV_ETH_TYPE_VLAN, &info);
    if(info.is_exists) {
        packet->vlan = info;
        packet->ol_flags |= PV_PKT_RX_VLAN | PV_PKT_RX_VLAN_STRIPPED;
    } else {
        packet->vlan.is_exists = false;
    }
}

void rx_offload_qinq_strip(const struct pv_nic* nic, struct pv_packet* const packet) {
    struct pv_vlan_info info;
    vlan_strip(nic, packet, PV_ETH_TYPE_QINQ, &info);
    if(info.is_exists) {
        packet->qinq = info;
        packet->ol_flags |= PV_PKT_RX_QINQ | PV_PKT_RX_QINQ_STRIPPED;
    } else {
        packet->qinq.is_exists = false;
    }
}

void vlan_strip(const struct pv_nic* nic, struct pv_packet* const packet, uint16_t const ethtype, struct pv_vlan_info* info) {

    uint32_t offload_type;
    uint32_t pkt_flag_vlan;
    switch(ethtype) {
    case PV_ETH_TYPE_VLAN:
        offload_type = DEV_RX_OFFLOAD_VLAN_STRIP;
        pkt_flag_vlan = PKT_RX_VLAN;
        break;
    case PV_ETH_TYPE_QINQ:
        offload_type = DEV_RX_OFFLOAD_QINQ_STRIP;
        pkt_flag_vlan = PKT_RX_QINQ;
        break;
    default:
        // Do not enter here
        assert(false);
    }

    info->is_exists = false;

    // IMPORTANT: Even If vlan is supported, qinq was not supported and using qinq, Must be SW decoded.
    bool must_fallback = (
        ethtype == PV_ETH_TYPE_VLAN &&
		packet->qinq.is_exists &&
		pv_nic_is_rx_not_usable(nic, DEV_RX_OFFLOAD_QINQ_STRIP)
    );

	if(pv_nic_is_rx_offload_supported(nic, offload_type) && !must_fallback) {
		struct rte_mbuf* const mbuf = packet->mbuf;
		if (mbuf->ol_flags & pkt_flag_vlan) {
            info->is_exists = true;
			info->tci = pv_vlan_uint16_to_tci(mbuf->vlan_tci);
		}
	} else {
		struct pv_ethernet* ether = (struct pv_ethernet*) pv_packet_data_start(packet);
		if (ether->type != ethtype) {
			return;
		}

		struct pv_vlan* vlan = (struct pv_vlan*)PV_ETH_PAYLOAD(ether);

        info->is_exists = true;
        info->tci = vlan->tci;

		// MAGIC: PV_ETHER_HDR_LEN - sizeof(ether->type) -- vlan->etype becomes ether->type
		memmove(pv_packet_data_start(packet) + PV_VLAN_HDR_LEN, pv_packet_data_start(packet), PV_ETH_HDR_LEN - sizeof(ether->type));

		packet->start += PV_VLAN_HDR_LEN;
	}
}

bool rx_offload_vlan_filter(const struct pv_nic* nic, struct pv_packet* const packet) {
	uint16_t vlan_id;
	if (packet->mbuf->ol_flags & PKT_RX_VLAN_STRIPPED) {
		// Already stripped by HW
		vlan_id = packet->mbuf->vlan_tci & 0x7f;
	} else {
		struct pv_ethernet* ether = (struct pv_ethernet*)pv_packet_data_start(packet);
		if(ether->type != PV_ETH_TYPE_VLAN) {
			return true;
		}
		struct pv_vlan* vlan = (struct pv_vlan*)PV_ETH_PAYLOAD(ether);
		vlan_id = vlan->tci.id;
	}

	struct pv_set* vlan_ids = nic->vlan_ids;
	return pv_set_contains(vlan_ids, &vlan_id);
}

void rx_offload_ipv4_checksum(const struct pv_nic* nic, struct pv_packet* const packet) {
	struct pv_ethernet * const ether = (struct pv_ethernet *)pv_packet_data_start(packet);
	struct rte_mbuf* const mbuf = packet->mbuf;

	if (ether->type != PV_ETH_TYPE_IPv4) {
		return;
	}

	if (pv_nic_is_rx_offload_supported(nic, DEV_RX_OFFLOAD_IPV4_CKSUM)) {
		uint32_t mask = mbuf->ol_flags & PKT_RX_IP_CKSUM_MASK;

		switch(mask) {
		case PKT_RX_IP_CKSUM_NONE:
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_NONE;
			break;
		case PKT_RX_IP_CKSUM_GOOD:
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_GOOD;
			break;
		case PKT_RX_IP_CKSUM_BAD:
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_BAD;
			break;
		case PKT_RX_IP_CKSUM_UNKNOWN:
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_UNKNOWN;
			break;
		}
	} else {
		struct pv_ipv4 * const ipv4 = (struct pv_ipv4 *)PV_ETH_PAYLOAD(ether);
		uint16_t pkt_checksum = ipv4->checksum;

		ipv4->checksum = 0;
		uint16_t calculated_checksum = checksum(ipv4, ipv4->hdr_len * 4);

		if (pkt_checksum == calculated_checksum) {
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_GOOD;
		} else {
			packet->ol_flags |= PV_PKT_RX_IP_CKSUM_BAD;
		}

		// Restore original checksum
		ipv4->checksum = pkt_checksum;
	}
}

void tx_offload_vlan_insert(const struct pv_nic* nic, struct pv_packet* const packet) {
    if(packet->vlan.is_exists) {
        vlan_insert(nic, packet, PV_ETH_TYPE_VLAN, &packet->vlan);
    }
}

void tx_offload_qinq_insert(const struct pv_nic* nic, struct pv_packet* const packet) {
    if(packet->qinq.is_exists) {
        puts("Insert qinq");
        vlan_insert(nic, packet, PV_ETH_TYPE_QINQ, &packet->qinq);
    }
}

void vlan_insert(const struct pv_nic* nic, struct pv_packet* const packet, uint16_t ethtype, struct pv_vlan_info* info) {

    uint64_t tx_flag;
    uint16_t* mbuf_tci;
	uint32_t offload_type;
    switch(ethtype) {
    case PV_ETH_TYPE_VLAN:
        tx_flag = PKT_TX_VLAN;
        mbuf_tci = &packet->mbuf->vlan_tci;
		offload_type = DEV_TX_OFFLOAD_VLAN_INSERT;
        break;
    case PV_ETH_TYPE_QINQ:
        tx_flag = PKT_TX_QINQ;
        mbuf_tci = &packet->mbuf->vlan_tci_outer;
		offload_type = DEV_TX_OFFLOAD_QINQ_INSERT;
        break;
    default:
        // Do not enter here
        assert(false);
    }

    // IMPORTANT: Even If vlan is supported, qinq was not supported and using qinq, Must be SW decoded.
    bool must_fallback = (
        ethtype == PV_ETH_TYPE_VLAN &&
		packet->qinq.is_exists &&
		pv_nic_is_tx_not_usable(nic, DEV_TX_OFFLOAD_QINQ_INSERT)
    );

	if(pv_nic_is_tx_offload_supported(nic, offload_type) && !must_fallback) {
		struct rte_mbuf *const mbuf = packet->mbuf;
		mbuf->ol_flags |= tx_flag;
		*mbuf_tci = pv_vlan_tci_to_uint16(info->tci);
	} else {

		void* start = pv_packet_data_start(packet);
		struct pv_ethernet* ether = (struct pv_ethernet*) start;
		memmove(start - PV_VLAN_HDR_LEN, start, PV_ETH_HDR_LEN - sizeof(ether->type));
		packet->start -= PV_VLAN_HDR_LEN;

		// Move to new header pos
		ether = (struct pv_ethernet*)pv_packet_data_start(packet);

		ether->type = ethtype;
		void* tci_pos = PV_ETH_PAYLOAD(ether);
		memcpy(tci_pos, &packet->vlan.tci, sizeof(packet->vlan.tci));
	}
}

void tx_offload_ipv4_checksum(const struct pv_nic* nic, struct pv_packet* const packet) {
	struct pv_ethernet* const ether = (struct pv_ethernet*)pv_packet_data_start(packet);
	struct pv_ipv4 * const ipv4 = (struct pv_ipv4 *)PV_ETH_PAYLOAD(ether);
	struct rte_mbuf* const mbuf = packet->mbuf;

	if(pv_nic_is_tx_offload_supported(nic, DEV_TX_OFFLOAD_IPV4_CKSUM)) {
		mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
		mbuf->l2_len = sizeof(struct pv_ethernet);
		mbuf->l3_len = ipv4->hdr_len * 4;
	} else {
		ipv4->checksum = 0;
		ipv4->checksum = checksum(ipv4, ipv4->hdr_len * 4);
	}
}
