#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#include "fill_packet.h"


int main(int argc, char* argv[])
{	
	int sockfd;
	int on = 1;
	
	pid_t pid = getpid();
	struct sockaddr_in dst;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int timeout = DEFAULT_TIMEOUT;

	char buf[500]; // 接收reply的buffer
	char interface[10]="";
	
	if (argc != 5) { // 簡易的判斷使用者輸入格式是否正確，若要嚴格判斷則用正規表達式
		printf("usage: sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]\n");
		exit(1);
	} else {
		strcpy(interface , argv[2]); // 使用者輸入之網卡界面
		timeout = atoi(argv[4]); // 將字串轉成整數
	}

	if(getuid() != 0) { // 判斷是否為root權限
		printf("You must to be a root!!\n");
		exit(1);
	}

	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0) // 建立socket並傳回檔案描述符號
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) // 設定socket參數, IP_HDRINCL讓我們可以編撰IP header
	{
		perror("setsockopt");
		exit(1);
	}
	

	// -----------------查找本機之ip位置與子網遮罩 

	struct in_addr src_ip, src_mask; //in_addr為用來存放IPv4位置的結構體
	struct ifreq ifr; // ifreq是用來配置和獲取ip地址、mask、MTU等信息的結構體
	ifr.ifr_addr.sa_family = AF_INET; // 想要獲得IPv4 address
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1); // 取得使用者輸入網卡之IPv4位址
	ioctl(sockfd, SIOCGIFADDR, &ifr); //引數為fd(檔案描述符)、request(ioctl要執行的動作、根據request的某種指標)，SIOCGIFADDR要求獲取界面位址
	src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr; //將ifr結構轉換成sockaddr_in結構後取得source ip

	//printf("source ip: %s\n", inet_ntoa(src_ip));

	ioctl(sockfd, SIOCGIFNETMASK, &ifr); //引數為fd(檔案描述符)、request(ioctl要執行的動作、根據request的某種指標)，SIOCGIFADDR要求獲取界面位址
	src_mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr; //將ifr結構轉換成sockaddr_in結構後取得mask

	//printf("source mask:  %s\n", inet_ntoa(src_mask));

	// ----------------判斷主機位置有多少個(total變數)
	int s[4], m[4], r[4], total = 1;
	sscanf(inet_ntoa(src_ip), "%d.%d.%d.%d", &s[0], &s[1], &s[2], &s[3]); 
	sscanf(inet_ntoa(src_mask), "%d.%d.%d.%d", &m[0] , &m[1], &m[2], &m[3]);
	for(int i=0; i<4; i++) {
		r[i] = 256 - m[i];
		if(r[i] > 1) total *= r[i]; // 計算hosts有多少個(包含了網路位置與廣播位置)
		//printf("s: %d, m: %d, r: %d, total: %d\n", s[i], m[i], r[i], total);
	}

	//printf("total hosts:  %d\n", total); // 列印出有多少的hosts主機要送包括網路位置、自己、 廣播位置

	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */


	struct timeval pktTimeout; // 該struct內部為  __time_t tv_sec; /* Seconds. */ 、 __suseconds_t tv_usec;  /* Microseconds. */ 
    pktTimeout.tv_usec = timeout; // 紀錄timeout(ms)的欄位
    pktTimeout.tv_sec = 0; // 不加此行的話執行速度會很慢
	clock_t start, end; // clock_t是一滴答(tick)數，1000個ticks為一秒
	
	struct iphdr *rcviphdr; // 接收回應之 ip header 指標
	struct icmphdr *rcvicmphdr; // 接收回應之 icmp header 指標
	int c = 0; // 紀錄不會送的主機個數
	for(int i=0; i<total; i++) {
		if(i == 0 || i == total-1) { // 跳過網路位置、廣播位置
			c++;
			continue; 
		}

		dst.sin_family = AF_INET; // 設定目的位置為IPv4協議
		char dst_ip[16];
		int d[4]; // 用來計算目的ip的分段
		for(int j=0; j<4; j++) { // 先將網路位置取得 
			d[j] = s[j] & m[j]; 
		}

		int tmp = i;
		for(int j=3; j>=0; j--) { 
			d[j] = d[j] + (tmp % 256); // 去計算目的ip位置
			tmp = tmp / 256;
		}

		sprintf(dst_ip, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]); //將ip分段以指定格式輸入到dst_ip變數內
		if(strncmp(dst_ip, inet_ntoa(src_ip), 16) == 0) { // 過濾掉自己的ip位置
			c++;
			continue;
		}

		dst.sin_family = PF_INET; // 設定目的IP的位置為IPv4協議
		inet_pton(AF_INET, dst_ip, &dst.sin_addr); // 將dst_ip轉換成網路傳送格式(big-endian)

		bzero(packet, sizeof(myicmp));
		fill_iphdr(&(packet->ip_hdr), dst_ip); // 填寫ip header部份
		fill_icmphdr(&(packet->icmp_hdr), pid, i+1-c); // 填寫 icmp header部份
		memset(packet->data, '\0', sizeof(packet->data));
		memcpy(packet->data, "M093040004", 12); // 設12是為了要符合PACKET_SIZE
		packet->icmp_hdr.checksum = fill_cksum(&(packet->icmp_hdr)); // 計算cksum

		printf("PING %s (data size = %lu , id = 0x%x , seq = %d , timeout = %d ms)\n", dst_ip, sizeof(packet->data), pid , i+1-c , timeout);

		if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&pktTimeout,sizeof(pktTimeout)) < 0) // SOL_SOCKET為通用socket, SO_RCVTIMEO讓我們可設定逾時時間
		{
			perror("setsockopt failed\n");
			exit(1);
		}

		start = clock(); // 使用clock()來紀錄送封包的時間
		if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) // 將ICMP封包送出
		{
			printf("\tDestination unreachable\n");
			continue;
		}

		memset(buf, 0, sizeof(buf)); // 將接收資料的buffer清空

		
		int recf = recv(sockfd, &buf, sizeof(buf),0); // recv用來將socket所接收到的資料塞進buffer, 同時會回傳接收到了多少位元組的大小
		if (recf < 0) {
			printf("\tDestination unreachable\n");
			continue;
		}
 
		end = clock(); // 使用clock()紀錄接收到封包的時間

		rcviphdr = (struct iphdr*)buf; // 指向ip header區段
		rcvicmphdr = (struct icmphdr*)(buf + (rcviphdr->ihl)*4); //指向icmp header區段

		if((end - start)/1000 < timeout && rcvicmphdr->type == 0) { // 確認接收到的是ICMP echo reply (type 0)
			printf("\tReply from : %s , time = %0.5f ms\n", dst_ip, (double)(end - start)/1000);
			continue;
		}
		
	}

	//printf("ok!!\n");

	return 0;
}

