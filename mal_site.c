#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#include <IPHlpApi.h>
#pragma comment(lib, "iphlpapi.lib")

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#endif

#define ETH_len 14
#define IP_len 20
#define TCP_len 20
#define TCP_payload ETH_len+IP_len+TCP_len

#define ETH_type 12
#define IP_prot 9

#define IP_chksum ETH_len+10
#define TCP_chksum ETH_len+IP_len+16

int my_MAC(unsigned char* mac) {
	PIP_ADAPTER_INFO info, pinfo=NULL;
	DWORD size = sizeof(info);
	int success=0;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}
	
	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if(pinfo) {
			success = 1;
		}
	}
	if (success) {
		memcpy(mac, pinfo->Address, 6);
	}

	free(info);
	return success;	// success 1 , fail 0
}

int my_IP(unsigned char* ipadd) {
	PIP_ADAPTER_INFO info, pinfo = NULL;
	DWORD size = sizeof(info);
	int success = 0;
	int chk, cnt;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}

	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if (pinfo) {
			success = 1;
		}
	}
	if (success) {
		chk = 0;
		cnt = 0;
		for (int i = 0; i<strlen(pinfo->IpAddressList.IpAddress.String); i++) {
			if (pinfo->IpAddressList.IpAddress.String[i] == '.') {
				ipadd[cnt] = chk;
				chk = 0;
				cnt++;
			}
			else {
				chk = chk * 10 + pinfo->IpAddressList.IpAddress.String[i] - 0x30;
			}
		}
		ipadd[cnt] = chk;
	}

	free(info);
	return success;	// success 1 , fail 0
}

int gateway_IP(unsigned char* gip) {
	PIP_ADAPTER_INFO info, pinfo = NULL;
	DWORD size = sizeof(info);
	int success = 0;
	int chk, cnt;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}

	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if (pinfo) {
			success = 1;
		}
	}
	if (success) {
		cnt = 0;
		chk = 0;
		for (int i = 0; i<strlen(pinfo->GatewayList.IpAddress.String); i++) {
			if (pinfo->GatewayList.IpAddress.String[i] == '.') {
				gip[cnt] = chk;
				chk = 0;
				cnt++;
			}
			else {
				chk = chk * 10 + pinfo->GatewayList.IpAddress.String[i] - 0x30;
			}
		}
		gip[cnt] = chk;
	}

	free(info);
	return success;	// success 1 , fail 0
}

// copied from my arp_poison
int make_request(u_char* pdata, u_char* tip) {
	int i;
	// broadcast
	for (i = 0; i<6; i++)
		pdata[i] = 0xFF;
	if (my_MAC(&pdata[6]) == 0) {
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	pdata[12] = 0x08;
	pdata[13] = 0x06;
	pdata[14] = 0x00;
	pdata[15] = 0x01;
	pdata[16] = 0x08;
	pdata[17] = 0x00;
	pdata[18] = 0x06;
	pdata[19] = 0x04;
	pdata[20] = 0x00;
	pdata[21] = 0x01; // request

	if (my_MAC(&pdata[22]) == 0) {
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	if (my_IP(&pdata[28]) == 0) {
		printf("Error : Writing my IP! \n");
		return 0;
	}
	for (i = 0; i<6; i++)
		pdata[32 + i] = 0x00;
	for (i = 0; i<4; i++)
		pdata[38 + i] = tip[i];

	return 1;

}

// copied from my arp_poison
int make_sp_me(u_char* arp_data, u_char* targetip, u_char* req_data) {
	int i;
	u_char fakeMAC[6];
	for (i = 0; i < 6; i++) {
		fakeMAC[i] = 'a';
	}

	// fake source mac (aa:aa:aa:aa:aa:aa)
	for (i = 0; i < 6; i++) {
		arp_data[6+i] = fakeMAC[i];
	}
	// fake sender mac
	for (i = 22; i < 28; i++) {
		arp_data[i] = fakeMAC[i-22];
	}

	// dst MAC (6-11) sender MAC (22-27)
	if (my_MAC(&arp_data[0]) == 0) {
		printf("Error : Writing my MAC address at packet ! \n");
	}
	// sender IP (28-31)  --  fake to victim
	if (gateway_IP(&arp_data[28]) == 0) {
		printf("Error : Can't read gateway address! \n");
	}
	// target MAC (me)
	my_MAC(&arp_data[32]);

	// target ip (38-41)
	for (i = 0; i<4; i++) {
		arp_data[38 + i] = targetip[i];
	}

	return 1;
}

// copied from my arp_poison
int make_sp_router(u_char* arp_data, u_char* targetip, u_char* req_data) {
	int i;
	u_char fakeMAC[6];
	for (i = 0; i < 6; i++) {
		fakeMAC[i] = 'a';
	}

	// fake source mac (aa:aa:aa:aa:aa:aa)
	for (i = 6; i < 12; i++) {
		arp_data[i] = fakeMAC[i-6];
	}
	// fake sender mac
	for (i = 22; i < 28; i++) {
		arp_data[i] = fakeMAC[i-22];
	}
	// target ip (38-41)
	if (gateway_IP(&arp_data[38]) == 0) {
		printf("Error : Can't read gateway address! \n");
	}
	// sender IP (28-31)  --  fake to router
	for (i = 0; i<4; i++) {
		arp_data[28 + i] = targetip[i];
	}
	// generating ARP request for ask router's MAC
	if (make_request(req_data, &arp_data[38]) == 0) {
		printf("Error : Making Request \n");
	}

	return 1;
}

int calc_checksum_IP(u_char* packet) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[IP_chksum] = 0x00;
	packet[IP_chksum + 1] = 0x00;

	for (i = 0; i < 10; i++) {
		checksum += c_packet[ETH_len / 2 + i];
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);

	packet[IP_chksum] = ((u_char*)&finalchk)[0];
	packet[IP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}

int calc_checksum_TCP(u_char* packet, unsigned int len) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[TCP_chksum] = 0x00;
	packet[TCP_chksum + 1] = 0x00;

	for (i = 0; i < 14; i++) {
		checksum += c_packet[(ETH_len + IP_len) / 2 + i];
	}
	for (i = 0; i < 4; i++) {
		checksum += c_packet[(ETH_len + 12) / 2 + i];
	}
	checksum += htons(0x0006);
	checksum += htons(0x001C);

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);
	packet[TCP_chksum] = ((u_char*)&finalchk)[0];
	packet[TCP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}

int main(int argc, char* argv[]) {
	FILE* fp;
	u_char block[100][100] = { 0, };
	int i,len=0;
	const int snaplen = 65536;

	u_char arp_data[42] = { 0, };
	u_char arp_data_r[42] = { 0, };
	u_char req_data[42] = { 0, };
	u_char targetip[4];
	u_char gatewip[4];
	u_char relaying_data[65536];

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	pcap_t *adhandle;
	int res, chk, chkk;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char* pkt_data;
	u_char block_data[ETH_len + IP_len + TCP_len + 8];
	time_t local_tv_sec;
	int count_reinfect = 0; // counter for check if they know that they are poisoned
	u_char fakeMAC[6];
	u_char myMAC[6];
	u_char gatewayMAC[6]; // setting at line 379

	u_char gzip[128] = { 31, -117, 8, 0, 0, 0, 0, 0, 0, 0, -29, 22, 98, -27, 96, 80, 120, -63, -34, -59, -104, -58, -63, 44, -108, 96, 92, 99, 100, 104, 102, 104, 105, 102, 97, 110, 82, -109, -100, -97, -85, -105, -107, -105, -103, -110, -102, -101, -81, -105, 88, 80, 80, -100, -97, 83, 90, -110, -103, -97, 7, 19, -85, 49, -84, 113, -12, -53, -15, -9, 8, -12, 79, 75, 115, 77, 116, -11, 44, 72, 118, 76, -12, -15, 12, 44, -9, 118, -85, 40, -48, 118, 13, -56, -86, 74, -52, 115, 45, -73, -75, -83, 49, 52, 49, 53, 54, 50, 52, 50, 51, 52, 53, 53, 48, -111, 98, -32, 1, 0, -106, 39, -125, -109, 114, 0, 0, 0 };

	my_MAC(myMAC);
	for (i = 0; i < 6; i++) {
		fakeMAC[i] = 'a';
	}

	// reading mal_site.txt
	fopen_s(&fp, "mal_site.txt", "r");
	while (fgets(block[len], 100, fp)) {
		for (i = 7;; i++) {
			if (block[len][i] == 0x0a) {
				if (block[len][i - 1] == '/') {
					block[len][i - 8] = 0x00;
				}
				else {
					block[len][i - 7] = 0x00;
				}
				break;
			}
			block[len][i - 7] = block[len][i];
		}
		len++;
	}
	len--;
	fclose(fp);

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	inum = 1;	// first device select

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	// Fixed Packet (ARP, type reply, ...)

	// type (ARP = 0x0806)
	arp_data[12] = 0x08;
	arp_data[13] = 0x06;
	// Ethernet = 0x0001
	arp_data[14] = 0x00;
	arp_data[15] = 0x01;
	// IP = 0x0800
	arp_data[16] = 0x08;
	arp_data[17] = 0x00;
	// MAC length (06)
	arp_data[18] = 0x06;
	// IP length (04)
	arp_data[19] = 0x04;
	// ARP type ( reply = 0x0002 )
	arp_data[20] = 0x00;
	arp_data[21] = 0x02;

	
	my_IP(&arp_data[28]);

////////////////////////////////////////////////////////////////////////////////

	gateway_IP(gatewip);
	// I am target
	my_IP(targetip);
	memcpy(arp_data_r, arp_data, 42);
	make_sp_me(arp_data, targetip, req_data);

// router spoofing ////////////////////////////////////////////////////////////

	make_sp_router(arp_data_r, targetip, req_data);

	// send ARP request to victim (broadcast)
	if (pcap_sendpacket(adhandle, req_data, 42) != 0) {
		printf("Error : Sending request packet!\n");
	}
	// catch arp relay packet
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* Timeout elapsed */
			continue;

		// type check
		if (ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0806) {
			// it's not ARP
			continue;
		}
		else { // It's ARP !
			if (ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002) {
				if (((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)(&req_data[38]))[0]) {
					for (i = 0; i<6; i++) {
						arp_data_r[i] = pkt_data[6 + i];
						arp_data_r[32 + i] = pkt_data[6 + i];
						gatewayMAC[i] = pkt_data[6 + i];
					}
					break;
				}
			}
		}
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	if (pcap_sendpacket(adhandle, arp_data, 42) != 0) {
		printf("Error : Sending request packet!\n");
	}

	printf("Spoofing me Finished\n");

	// send ARP spoofing packet
	if (pcap_sendpacket(adhandle, arp_data_r, 42) != 0) {
		printf("Error : Sending request packet!\n");
	}
	
	printf("Spoofing router Finished\n");

//////////////////////////////////////////////////////////////////////////////////////////

// 위의 내용은 이전 과제를 windows에 맞게 살짝 수정한 내용입니다.
// 또한 감염 타겟을 자기자신으로 고정시켰습니다.
// router knows that my MAC is aa:aa:aa:aa:aa:aa
// my computer knows that router MAC is aa:aa:aa:aa:aa:aa


	// relay and re-infecting and blocking mal site
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* Timeout elapsed */
			continue;
		if (count_reinfect > 30) {
			count_reinfect = 0;
			if (pcap_sendpacket(adhandle, arp_data, 42) != 0) {
				printf("Error : Sending arp spoofing packet to victim !\n");
			}
			if (pcap_sendpacket(adhandle, arp_data_r, 42) != 0) {
				printf("Error : Sending arp spoofing packet to router !\n");
			}
			printf("Spoofing Victim and Router again Finished\n");
		}

		// re-infecting ( copied from my arp_poison assignment )
		if (ntohs(*((unsigned short*)(&pkt_data[12]))) == 0x0806) {
			count_reinfect++; // if arp packet is increased, then router and victim smell the spoofing
							  // if arp -> check for recognizing it is arp recovery
			
			if (ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002) { // reply
																		// sender ip = victim ip ?
				
		////////// checking reply is mine (내가 한 reply인지 확인)//////////
				chk = 1;
				for (i = 0; i < 6; i++) {
					chk &= (pkt_data[6 + i] == fakeMAC[i]);
				}
				if (chk) continue;
		////////////////////////////////////////////////////////////////////
				if ((((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)targetip)[0])) {
					// target ip = router ?
					// !! target is recovering router !!
					printf("Detected Recovering Router\n");
					if (pcap_sendpacket(adhandle, arp_data_r, 42) != 0) {
						printf("Error : Sending arp spoofing packet to router !\n");
					}
					printf(" -> Spoofing Router again Finished\n");
					//}
				}
				// sender ip = router ip ?
				else if ((((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)gatewip)[0])) {
					// target ip = victim ip ?
					// !! target is recovering victim !!
					printf("Detected Recovering Victim\n");
					if (pcap_sendpacket(adhandle, arp_data, 42) != 0) {
						printf("Error : Sending arp spoofing packet to victim !\n");
					}
					printf(" -> Spoofing Victim again Finished\n");
				}
			}
			
			
		}

		// relaying and blocking mal_site
		else {
			// if destination mac is fakeMAC
			chk = 1;
			for (i = 0; i < 6; i++) {
				chk &= (pkt_data[i] == fakeMAC[i]);
			}
			if (chk) {
				chkk = 1;
				// determining who send this packet (chkk = 1 : me , chkk = 0 : router)
				for (i = 6; i < 12; i++) {
					chkk &= (pkt_data[i] == myMAC[i-6]);
				}
				if (chkk) { // my computer send this packet, so destination is router
					for (i = 0; i < 6; i++) {
						relaying_data[i] = gatewayMAC[i];
						relaying_data[6 + i] = myMAC[i];
					}
				}
				else {
					for (i = 0; i < 6; i++) {
						relaying_data[i] = myMAC[i];
						relaying_data[6 + i] = gatewayMAC[i];
					}
				}
				// other contents are same as original packet
				for (i = 12; i < (header->caplen); i++) {
					relaying_data[i] = pkt_data[i];
				}

				// checking this packet contains mal_site
				for (i = 0; i < len; i++) {
					if (strstr(&relaying_data[54], block[i])) {
						local_tv_sec = header->ts.tv_sec;
						localtime_s(&ltime, &local_tv_sec);
						strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

						printf("%s | approach to \"http://%s\" blocked!\n", timestr,block[i]);
						
////////////////////// backward FIN send
						for (i = 0; i < (ETH_len + IP_len) + 4; i++) {
							block_data[i] = pkt_data[i];
						}
						// ip change
						for (i = 0; i < 4; i++) {
							block_data[ETH_len + 12 + i] = pkt_data[ETH_len + 16 + i];
							block_data[ETH_len + 16 + i] = pkt_data[ETH_len + 12 + i];
						}
						block_data[ETH_len + 1] = 0x44;
						block_data[ETH_len + 2] = 0x00;
						block_data[ETH_len + 3] = 0x30;
						block_data[ETH_len + 4] = 0x77;
						block_data[ETH_len + 5] = 0xbf;
						calc_checksum_IP(block_data);
						// port change
						for (i = 0; i < 2; i++) {
							block_data[ETH_len + IP_len + i] = pkt_data[ETH_len + IP_len + 2 + i];
							block_data[ETH_len + IP_len + 2 + i] = pkt_data[ETH_len + IP_len + i];
						}
						// seq <-> ack change
						for (i = 0; i < 4; i++) {
							block_data[ETH_len + IP_len + 4 + i] = pkt_data[ETH_len + IP_len + 8 + i];
							block_data[ETH_len + IP_len + 8 + i] = pkt_data[ETH_len + IP_len + 4 + i];
						}
						i = (ETH_len + IP_len + 12);
						block_data[i++] = 0x50;
						block_data[i++] = 0x11;
						for (; i < (ETH_len + IP_len + 16); i++) {
							block_data[i] = pkt_data[i];
						}
						for (int j = 0; j < 4; j++) {
							block_data[i++] = 0x00;
						}
						block_data[i++] = 'b';
						block_data[i++] = 'l';
						block_data[i++] = 'o';
						block_data[i++] = 'c';
						block_data[i++] = 'k';
						block_data[i++] = 'e';
						block_data[i++] = 'd';
						block_data[i++] = '!';
						block_data[0x30] = 0x00;
						block_data[0x31] = 0x00;
						calc_checksum_TCP(block_data, i);

						if (pcap_sendpacket(adhandle, block_data, i) != 0) {
							printf("Error : Sending backward FIN packet to victim !\n");
						}
//////////////////////////////////////////////
						break;
					}
				}
				// if there is no mal_site, send packet to relay
				if (i == len) {
					if (pcap_sendpacket(adhandle, relaying_data, header->caplen) != 0) {
						printf("Error: relaying packet\n");
					}
				}

			}
		}
	}
//	system("pause");
	return 0;
}