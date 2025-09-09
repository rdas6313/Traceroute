
#ifndef TRACEROUTE_HEADER
#define TRACEROUTE_HEADER

#include <stdio.h>           // printf, perror
#include <stdlib.h>          // exit
#include <string.h>          // memset, memcpy, strlen
#include <unistd.h>          // close()
#include <sys/types.h>       // data types
#include <sys/socket.h>      // socket(), sendto(), recvfrom()
#include <arpa/inet.h>       // inet_addr, htons, htonl
#include <netinet/in.h>      // sockaddr_in, IPPROTO_ICMP
#include <netinet/ip_icmp.h> // struct icmphdr, ICMP types
#include <stdint.h>          // exact-width integer type
#include <sys/time.h>        // time related operation
#include <linux/errqueue.h>  // ErrorQueue header
#include <errno.h>           // defines errno, EAGAIN, EWOULDBLOCK, etc.
#include <netinet/ip.h>      // ip header
#include <netinet/ip_icmp.h> //icmp header
#include <netinet/udp.h>     // udp header
#include <netdb.h>

#define DEFAULT_MAX_HOP 32
#define DEFAULT_DEST_PORT 40254
#define MY_PORT 50000
#define DEFAULT_RECV_TIMEOUT 3 // in sec
#define BUFFER_SIZE 1500
#define TYPE_TTL_EXPIRED 11
#define CODE_TTL_EXPIRED 0
#define ICMP_TTL_EXPIRED 1
#define ICMP_UNREACHABLE 2
#define IP_ADDR_LEN 35

/*
 *   Trace related option from user
 *
 */
typedef struct TraceIn_t
{
    uint8_t timeout;
    uint8_t max_hop;
    uint8_t skip_dns;
    uint16_t des_port;
    uint8_t des_ip[IP_ADDR_LEN];
    void (*callback)(double ms1, double ms2, double ms3, char offender_ip1[], char offender_ip2[], char offender_ip3[]);
} TraceIn_t;

typedef struct SocketIn_t
{
    int32_t usock_fd; // for udp
    int32_t isock_fd; // for icmp
    TraceIn_t *trace_data;
} SocketIn_t;

typedef struct ProbeMsg_t
{
    struct timeval send_time;
    struct timeval recv_time;
    char offender_ip[IP_ADDR_LEN];
    uint8_t icmp_error;
} ProbeMsg_t;

int8_t startTrace(void);
TraceIn_t *configureTrace(void);
int8_t getDomainName(char *ip, char *domain, uint32_t domainSize);

#endif