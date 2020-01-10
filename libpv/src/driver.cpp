#include <stdio.h>
#include <string.h>
#include <iostream>
#include <pv/packet.h>
#include <pv/driver.h>

#include <pv/ethernet.h>
#include <pv/ipv4.h>
#include <pv/icmp.h>

namespace pv {

#define MAX_PACKETLETS	8

uint32_t packetlet_count;
class Packetlet* packetlets[MAX_PACKETLETS];

static bool received(uint32_t queueId, uint64_t addr, uint8_t* payload, uint32_t start, uint32_t end, uint32_t size) {
	Packet* packet = new Packet(queueId, addr, payload, start, end, size);

	for(uint32_t i = 0; i < packetlet_count; i++) {
		try {
			if(packetlets[i] != nullptr && packetlets[i]->received(packet))
				return true;
		} catch(const std::exception& e) {
			fprintf(stderr, "Exception occurred: Packetlet[%u] - %s\n", i, e.what());
			printf("Exception occurred: Packetlet[%u] - %s\n", i, e.what());
		} catch(...) {
			fprintf(stderr, "Unexpected exception occurred: Packetlet[%u]\n", i);
			printf("Unexpected exception occurred: Packetlet[%u]\n", i);
		}
	}

	delete packet;

	return false;
}

static struct pv_Callback* callback;

static struct pv_Driver driver = {
	.received = pv::received
};

extern "C" {

class MyPacketlet: public Packetlet {
public:
	MyPacketlet();
	bool received(Packet* packet);
};

MyPacketlet::MyPacketlet() : Packetlet() {
}

bool MyPacketlet::received(Packet* packet) {
	printf("received in packetlet\n");
	std::cout << packet << std::endl;

/*
uint8_t pl[] = { 
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
0x00, 0x54, 0x3e, 0x01, 0x40, 0x00, 0x40, 0x01, 0xfe, 0xa5, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 
0x00, 0x01, 0x08, 0x00, 0xbb, 0xe6, 0x0d, 0xd2, 0x00, 0x01, 0x60, 0x36, 0x17, 0x5e, 0x00, 0x00, 
0x00, 0x00, 0xf4, 0xde, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 
0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 
0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 
0x36, 0x37, 
};
	memcpy(packet->payload, pl, sizeof(pl));
*/

	Ethernet* ether = new Ethernet(packet);
	std::cout << ether << std::endl;

	if(ether->getType() == ETHER_TYPE_IPv4) {
		IPv4* ipv4 = new IPv4(packet, ether->getPayloadOffset());
		std::cout << ipv4 << std::endl;

		if(ipv4->getProto() == IP_PROTOCOL_ICMP && ipv4->getDst() == 0x7f000001) { // 127.0.0.1
			ICMP* icmp = new ICMP(packet, ipv4->getBodyOffset());
			std::cout << icmp << std::endl;

			if(icmp->getType() == 8) {
				icmp->setType(0) // ICMP reply
					->setChecksum(0)
					->setChecksum(icmp->checksum(0, icmp->getEnd() - icmp->getOffset()));
				
				uint32_t addr = ipv4->getSrc();
				ipv4->setDst(ipv4->getSrc())
				    ->setSrc(addr)
				    ->setTtl(64)
				    ->setDf(false)
				    ->setId(ipv4->getId() + 1)
				    ->setChecksum(0)
				    ->setChecksum(ipv4->checksum(0, ipv4->getHdrLen() * 4));

				uint64_t mac = ether->getDst();
				ether->setDst(ether->getSrc())
				     ->setSrc(mac);

				for(uint32_t i = packet->start; i < packet->end; i++) {
					printf("%02x ", packet->payload[i]);
				}
				printf("\n");

				delete icmp;
				delete ipv4;
				delete ether;

				if(!send(packet)) {
					fprintf(stderr, "Cannot reply icmp\n");
					return false;
				} else {
					return true;
				}
			}

			delete icmp;
		}

		delete ipv4;
	}

	delete ether;

	return false;
}

struct pv_Driver* pv_init(struct pv_Callback* cb) {
	callback = cb;

	new MyPacketlet();

	return &driver;
}

} // extern "C"

int32_t pv_driver_add_packetlet(void* packetlet) {
	if(packetlet_count < MAX_PACKETLETS) {
		packetlets[packetlet_count++] = (Packetlet*)packetlet;
		return packetlet_count - 1;
	}

	return -1;
}

bool pv_driver_remove_packetlet(void* packetlet) {
	for(uint32_t i = 0; i < packetlet_count; i++) {
		if(packetlets[i] != nullptr) {
			if((void*)packetlets[i] == packetlet) {
				packetlets[i] = nullptr;
				return true;
			}
		}
	}

	return false;
}

bool pv_driver_alloc(uint64_t* addr, uint8_t** payload, uint32_t size) {
	if(callback == nullptr) {
		fprintf(stderr, "Packetvisor driver is not inited yet\n");
		return false;
	}

	return callback->alloc(addr, payload, size);
}

void pv_driver_free(uint64_t addr) {
	if(callback == nullptr) {
		fprintf(stderr, "Packetvisor driver is not inited yet\n");
		return;
	}

	return callback->free(addr);
}

bool pv_driver_send(uint32_t queueId, uint64_t addr, uint8_t* payload, uint32_t start, uint32_t end, uint32_t size) {
	if(callback == nullptr) {
		fprintf(stderr, "Packetvisor driver is not inited yet\n");
		return false;
	}

	return callback->send(queueId, addr, payload, start, end, size);
}

}; // namespace pv
