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