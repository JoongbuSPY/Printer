#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>

#include "windivert.h"

#include <pcap.h>
#include <stdio.h> 
#include <stdlib.h>
#include <time.h>
#define		HAVE_REMOTE
#include		"pcap.h"			
#include		"remote-ext.h"

#define		PACKET_SIZE		1000

#define MAXBUF  0xFFFF

using namespace std;

int main(int argc, char **argv)
{
	pcap_if_t	*alldevs;		// pcap ��ġ ���� ���� ����ü
	pcap_if_t	*d;				// pcap ��ġ �������̽� ����ü
	pcap_t		*adhandle;	// ��ġ ���� �� ����ü 

	char errbuf[PCAP_ERRBUF_SIZE];
	int  i, inum, no_interface = 0;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{									// pcap_open()���� �� �� �ִ� ��ġ list ���� �Լ�
										// �˻��� ��ġ��ġ, null, ��ġ ���� ����, �����޼��� ���� ����
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	printf("\n>> ��Ʈ��ũ �������̽� ī��\n");

	for (d = alldevs; d; d = d->next)	// ������ ��ġ list ���  
	{
		printf("\n   %d) %s", ++no_interface, d->name);
		if (d->description) printf("\n      (%s)\n", d->description);
		else printf("(No description available)\n");
	}


	if (no_interface == 0)
	{
		printf("\7\7\n>> �������̽��� Ȯ�ε��� �ʽ��ϴ� ! WinPcap ��ġ ���θ� �����ϼ��� !\n");
		return -1;
	}

	printf("\7\7\n.. �ش� �������̽� ��ȣ�� �����ϼ��� (1-%d) ? ", no_interface);
	scanf("%d", &inum);
	if (inum < 1 || inum > no_interface)
	{
		printf("\n>> �������̽� ��ȣ ���� !\n");
		pcap_freealldevs(alldevs);    // ���� �Ҵ��� ������ free
		return -1;
	}
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf))
		== NULL)		// ��ġ �̸�, ĸ�� ������ ũ��, ���, timeout, ������ġ ����, �������� ũ��
	{
		fprintf(stderr, "\n>> adapter open ���� ! %s�� WinPcap���� �������� �ʽ��ϴ� !\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n\nListening on %s\n", d->description);

	HANDLE handle, console;
	INT16 priority = 0;
	char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	int flag = 0;

	console = GetStdHandle(STD_OUTPUT_HANDLE);

	//"(outbound and tcp.DstPort == 7070) and (inbound and ip.SrcAddr == 192.168.1.193)"

	handle = WinDivertOpen("(outbound and tcp.DstPort == 7070)", WINDIVERT_LAYER_NETWORK, priority, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n", GetLastError());
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL);

		SetConsoleTextAttribute(console, FOREGROUND_RED);


		if (tcp_header != NULL)
		{
			SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

			//for (int i = 0; i < packet_len; i++)
			//cout << packet[i];

			string str;

			for (int i = 0; i < packet_len; i++)
				str += packet[i];


			if (str.find("loginId=FAFA9121&passwd=9121FAFA") != string::npos)
			{
				str.replace(str.find("loginId=FAFA9121&passwd=9121FAFA"), strlen("loginId=FAFA9121&passwd=9121FAFA"), "loginId=FAFA6361&passwd=6361FAFA");
				//cout << str << endl << "str�� ����: " << str.length();

				//cout << str;

				memcpy(packet, str.c_str(), str.length());

				WinDivertHelperCalcChecksums(packet, packet_len, 0);

				if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
				{
					printf("WinDivertSend Error!!\n");
					break;
				}
				else
				{
					SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_INTENSITY);

					system("cls");
					cout << endl << "----------------------------------------------------------------------------------------" << endl;
					cout << "-----------------------------------Change-----------------------------------------------" << endl;
					cout << "----------------------------------------------------------------------------------------" << endl;

					for (int i = 0; i < str.length(); i++)
						cout << packet[i];
				}
			}

			//for (int i = 0; i < packet_len; i++)
			//cout << aasdf[i];
			WinDivertHelperCalcChecksums(packet, packet_len, 0);

			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				printf("WinDivertSend Error!!\n");
				break;
			}
		}


	}
}
