#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#include <IPHlpApi.h>
#pragma comment(lib, "iphlpapi.lib")

#include <winsock.h>
#include <winsock2.h>
#include <WS2tcpip.h>

int my_MACnIP(unsigned char* mac, unsigned char* ipadd) {
	PIP_ADAPTER_INFO info, pinfo=NULL;
	DWORD size = sizeof(info);
	int success=0;
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
		if(pinfo) {
			success = 1;
		}
	}
	if (success) {
		memcpy(mac, pinfo->Address, 6);
		chk = 0;
		cnt = 0;
		for(int i=0;i<strlen(pinfo->IpAddressList.IpAddress.String);i++){
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
	for (i = 0; i<6; i++)
		pdata[i] = 0xFF;
	if (eth0_MAC(&pdata[6]) == 0) {
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

	if (my_MACnIP(&pdata[22],&pdata[28]) == 0) {
		printf("Error : Writing my IP and MAC! \n");
		return 0;
	}
	for (i = 0; i<6; i++)
		pdata[32 + i] = 0x00;
	for (i = 0; i<4; i++)
		pdata[38 + i] = tip[i];

	return 1;

}

// copied from my arp_poison
int make_sp_target(u_char* arp_data, u_char* targetip, u_char* req_data) {
	int i;

	// source MAC (6-11)
	if (eth0_MAC(&arp_data[6]) == 0) {
		printf("Error : Writing my MAC address at packet ! \n");
	}
	// sender MAC (22-27)
	if (eth0_MAC(&arp_data[22]) == 0) {
		printf("Error : Writing my MAC address at packet ! \n");
	}
	// sender IP (28-31)  --  fake to victim
	if (gatewayIP(&arp_data[28]) == 0) {
		printf("Error : Can't read gateway address! \n");
	}
	// target ip (38-41)
	for (i = 0; i<4; i++) {
		arp_data[38 + i] = targetip[i];
	}

	// generating ARP request for ask victim's MAC
	if (make_request(req_data, targetip) == 0) {
		printf("Error : Making Request \n");
	}
	return 1;
}

// copied from my arp_poison
int make_sp_router(u_char* arp_data, u_char* targetip, u_char* req_data) {
	int i;

	// target ip (38-41)
	if (gatewayIP(&arp_data[38]) == 0) {
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


int main(int argc, char* argv[]) {
	FILE* fp;
	char* block[100][100];
	int i,len=0;
	u_char req_data[42] = { 0, };

	// reading mal_site.txt
	fopen_s(&fp, "mal_site.txt", "r");
	while (fgets(block[len], 100, fp)) {
		len++;
	}
	fclose(fp);

	my_MACnIP(&req_data[0], &req_data[6]);
	gateway_IP(&req_data[10]);
	for (i = 0; i < 6; i++) {
		printf("%02x ", req_data[i]);
	}
	printf("\n");
	for (i = 0; i < 8; i++) {
		printf("%d.", req_data[6 + i]);
	}
	printf("\n");

//	system("pause");
	return 0;
}