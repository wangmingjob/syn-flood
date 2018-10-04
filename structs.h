#ifndef STRUCTS_H_INCLUDE
#define STRUCTS_H_INCLUDE
#ifdef __cplusplus
extern "C"
{
#endif
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETH_ALEN 6
#define ETH_HLAN 14
#define ETH_ZLEN 60
#define ETH_DATA_LEN 1500
#define ETH_FRAME_LEN 1514
#define ETH_FCS_LEN 4
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define ETH_P_PAE 0x888E

#pragma pack(1)

	typedef struct
	{
		uint32_t saddr;   /* ip头部源地址 */
		uint32_t daddr;   /* ip头部目的地址 */
		uint8_t mbz;	  /* 补全字段，需为0 */
		uint8_t protocol; /* ip头部协议 */
		uint16_t tcpl;	/* tcp长度，包括头部和数据部分 */
	} sniff_tcpchecksum;

	/* ETH头 */
	typedef struct
	{
		/* 目标机器Mac地址 */
		uint8_t ether_dhost[ETH_ALEN];
		/* 发送机器Mac地址 */
		uint8_t ether_shost[ETH_ALEN];
		/* eth类型 IP:0x0800,ARP:0x0806,REVARP:0x8035,IPV6:0x86dd */
		uint16_t ether_type;
	} sniff_ethernet;

	/* IP header */
	typedef struct
	{
#if __BYTE_ORDER == __LITTLE_ENDIAN
		/* 首部长度，头部数据长度，需要*4为字节数 */
		uint8_t ip_hlen : 4;
		/* 版本,IPv4为4 */
		uint8_t ip_ver : 4;
#else
	/* 版本,IPv4为4 */
	uint8_t ip_ver : 4;
	/* 首部长度，头部数据长度，需要*4为字节数 */
	uint8_t ip_hlen : 4;
#endif

		/* 服务类型，流量控制相关 */
		uint8_t ip_tos;
		/* 总长度(包含IP头) */
		uint16_t ip_len;
		/* 数据流标识（每个数据流标识一致） */
		uint16_t ip_id;
		/* 保留位 */
		uint8_t ip_flag_reserved : 1;
		/* DF禁止分片 */
		uint8_t ip_flag_df : 1;
		/* MF更多分片 */
		uint8_t ip_flag_mf : 1;
		/* 分片偏移 */
		uint16_t ip_off : 13;
		/* 生存时间，路由用 */
		uint8_t ip_ttl;
		/* 协议类型
		   ICMP 1
		   TCP 6
		   UDP 17
		   */
		uint8_t ip_p;
		/* 头部校验和 */
		uint16_t ip_sum;
		/* 源地址 */
		uint32_t ip_src;
		/* 目标地址 */
		uint32_t ip_dst;
	} sniff_ip;
	/* TCP header */
	typedef struct
	{
		/* 源端口 */
		uint16_t th_sport;
		/* 目标端口 */
		uint16_t th_dport;
		/* sequence编号 */
		uint32_t th_seq;
		/* acknowledgement编号 */
		uint32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
		/* 保留位 */
		uint16_t th_res1 : 4;
		/* 首部长度，头部数据长度，需要*4为字节数 */
		uint16_t th_hlen : 4;
		uint16_t th_flag_fin : 1;
		/* SYN */
		uint16_t th_flag_syn : 1;
		/* RST */
		uint16_t th_flag_rst : 1;
		/* PSH */
		uint16_t th_flag_psh : 1;
		/* ACK */
		uint16_t th_flag_ack : 1;
		/* URG */
		uint16_t th_flag_urg : 1;
		/* 保留位 */
		uint16_t th_res2 : 2;
#else
	/* 首部长度，头部数据长度，需要*4为字节数 */
	uint8_t th_hlen : 4;
	/* 保留位 */
	uint8_t th_res1 : 4;
	/* 保留位 */
	uint8_t th_res2 : 2;
	/* URG */
	uint8_t th_flag_urg : 1;
	/* ACK */
	uint8_t th_flag_ack : 1;
	/* PSH */
	uint8_t th_flag_psh : 1;
	/* RST */
	uint8_t th_flag_rst : 1;
	/* SYN */
	uint8_t th_flag_syn : 1;
	/* FIN */
	uint8_t th_flag_fin : 1;
#endif
		/* 滑动窗口大小 */
		uint16_t th_win;
		/* checksum */
		uint16_t th_sum;
		/* 紧急指针 */
		uint16_t th_urp;
	} sniff_tcp;
#pragma pack(0)
#ifdef __cplusplus
}
#endif
#endif //STRUCTS_H_INCLUDE