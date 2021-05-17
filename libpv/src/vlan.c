#include <pv/net/vlan.h>

inline uint16_t pv_vlan_tci_to_uint16(struct pv_vlan_tci tci) {
    return ntohs(*((uint16_t*)(void*)&tci));
}

inline struct pv_vlan_tci pv_vlan_uint16_to_tci(uint16_t tci) {
    struct pv_vlan_tci vlan_tci;
    vlan_tci.priority = tci >> 13 & 0b111;
    vlan_tci.cfi = tci >> 12 & 0b1;
    vlan_tci.id = tci >> 0 & 0x7f;

    return vlan_tci;
}
