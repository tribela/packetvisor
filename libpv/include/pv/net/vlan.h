#ifndef __PV_NET_VLAN_H__
#define __PV_NET_VLAN_H__

#include <stdint.h>
#include <netinet/in.h>

#define PV_VLAN_HDR_LEN (sizeof(struct pv_vlan))

struct pv_vlan_tci {
    uint8_t priority: 3;
    uint8_t cfi: 1;
    uint16_t id: 12;
} __attribute__ ((packed, scalar_storage_order("big-endian")));

struct pv_vlan {
    struct pv_vlan_tci tci;
    uint16_t etype;
} __attribute__ ((packed, scalar_storage_order("big-endian")));

uint16_t pv_vlan_tci_to_uint16(struct pv_vlan_tci tci);

struct pv_vlan_tci pv_vlan_uint16_to_tci(uint16_t tci);

#endif
