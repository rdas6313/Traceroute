
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

#define DEFAULT_MAX_HOP 32
#define DEFAULT_DEST_PORT 40254
#define MY_PORT 50000
#define DEFAULT_RECV_TIMEOUT 3 // in sec
#define BUFFER_SIZE 1500
#define TYPE_TTL_EXPIRED 11
#define CODE_TTL_EXPIRED 0
#define ICMP_TTL_EXPIRED 1
#define ICMP_UNREACHABLE 2

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
    uint8_t des_ip[33];
    void (*callback)(uint8_t ms1, uint8_t ms2, uint8_t ms3, char offender_ip[]);
} TraceIn_t;

typedef struct SocketIn_t
{
    int32_t sockfd;
    TraceIn_t *trace_data;
} SocketIn_t;

typedef struct ProbeMsg_t
{
    struct timeval send_time;
    struct timeval recv_time;
    char offender_ip[33];
    uint8_t icmp_error;
} ProbeMsg_t;



// void release_resource(void);
// uint8_t checkInputError();
// int8_t socketConfigure();
// int8_t sendProbeMsg(ProbeMsg_t *pmsg, int total_probe);
// int8_t changeTTL(int8_t ttl);
// int8_t captureICMP(ProbeMsg_t *pmsg, uint8_t total_probe);
// int8_t initiate_callback(ProbeMsg_t *probeMsg, uint8_t total_probe);
// int8_t start_tracing();
int8_t startTrace(void);
TraceIn_t *configureTrace(void);

#endif