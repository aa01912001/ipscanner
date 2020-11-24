#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>


void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{	
	ip_hdr->ip_v = 4; // 版本號 IPv4
	ip_hdr->ip_hl = 5; // header length 20bytes 每一單位代表4bytes
	ip_hdr->ip_id = 0; // identification 封包識別用
	ip_hdr->ip_off = htons(IP_DF); // don't fragment 超過MTU也不進行封包切割
	ip_hdr->ip_ttl = 1; // TTL = 1使封包不會跑出gateway外
	ip_hdr->ip_p = IPPROTO_ICMP; // Protocol
	inet_pton(AF_INET, dst_ip, &ip_hdr->ip_dst); // 將目的位置轉成網路格式放入header
}

void
fill_icmphdr (struct icmphdr *icmp_hdr, pid_t pid, int seq)
{
	icmp_hdr->type = ICMP_ECHO; // type
	icmp_hdr->code = 0; // code = 0為ICMP echo request
	// checksum之後算
	icmp_hdr->un.echo.id = htons(pid); // identifier
	icmp_hdr->un.echo.sequence = htons(seq); // sequence number
}

u16
fill_cksum(struct icmphdr* icmp_hdr)
{	
	/*  checksum計算方式
	1、 先將需要計算checksum數據中的checksum設爲0； 
	2、 計算checksum的數據按2byte劃分開來，每2byte組成一個16bit的值，如果最後有單個byte的數據，補一個byte的0組成2byte； 
	3、 將所有的16bit值累加到一個32bit的值中； 
	4、 將32bit值的高16bit與低16bit相加到一個新的32bit值中，若新的32bit值大於0Xffff, 再將新值的高16bit與低16bit相加； 
	5、 將上一步計算所得的16bit值按位取反，即得到checksum值，存入數據的checksum字段即可*/
	unsigned short * tmp = (unsigned short *)icmp_hdr;
	int size = ICMP_PACKET_SIZE;
	unsigned long cksum = 0; // 步驟1

	while(size > 1) { // 步驟 2、3 
		cksum += *tmp;
		tmp++;
		size -= 2;
	}
	if(size == 1) cksum += (*(unsigned char *)tmp) << 2;

	cksum = (cksum >> 16) + (cksum & 0xffff); // 步驟4
	cksum += cksum >> 16;
	if((cksum & 0xffff0000UL) != 0) {
		cksum = (cksum >> 16) + (cksum & 0xffff); 
	}


	cksum = ~cksum; // 步驟5
	
	return cksum;
}