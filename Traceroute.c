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

#define MY_PORT 50000
#define DEFAULT_RECV_TIMEOUT 3

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
    uint32_t des_ip;
    void (*callback)();
} TraceIn_t;

typedef struct SocketIn_t
{
    int32_t sockfd;
    TraceIn_t *trace_data;
} SocketIn_t;

typedef struct ProbeTime_t
{
    struct timeval send_time;
    struct timeval recv_time;
} ProbeTime_t;

SocketIn_t *socket_data;

TraceIn_t *configureTrace(void)
{

    if (socket_data == NULL)
    {
        socket_data = (SocketIn_t *)malloc(sizeof(SocketIn_t));
        socket_data->trace_data = (TraceIn_t *)malloc(sizeof(TraceIn_t));
    }
    return socket_data->trace_data;
}

void startTrace()
{
}

int8_t socketConfigure()
{
    if (socket_data == NULL)
    {
        perror("SOCKETDATA: NOT INTIALIZED");
        return -1;
    }
    else if (socket_data->trace_data == NULL)
    {
        perror("TRACEDATA: NOT INTIALIZED");
        return -1;
    }

    // creating socket
    socket_data->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_data->sockfd < 0)
    {
        perror("SOCKET INTIALIZATION ERROR");
        return -1;
    }
    // initialization for socket address
    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = INADDR_ANY;
    myaddr.sin_port = htons(MY_PORT);

    // binding traceroute to a specific ip/port
    if (bind(socket_data->sockfd, (const struct sockaddr *)&myaddr, sizeof(myaddr)) < 0)
    {
        perror("BIND FAILED");
        return -1;
    }

    // Setting CUSTOM RECV TIMER
    uint8_t timeout_s = socket_data->trace_data->timeout == 0 ? DEFAULT_RECV_TIMEOUT : socket_data->trace_data->timeout;
    struct timeval tv = {timeout_s, 0};
    if (setsockopt(socket_data->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv)) < 0)
    {
        perror("CUSTOM RECV TIME FAILED");
        return -1;
    }
    // Setting ICMP ERROR RECEPTION
    uint8_t enable = 1;
    if (setsockopt(socket_data->sockfd, IPPROTO_IP, IP_RECVERR, (const void *)&enable, sizeof(enable)) < 0)
    {
        perror("ICMP ERROR RECEPTION ON FAILED");
        return -1;
    }
    return 1;
}



int8_t sendProbeMsg(ProbeTime_t *ptime, int total_probe)
{

    const char *dest_ip = socket_data->trace_data->des_ip;
    uint16_t dest_port = socket_data->trace_data->des_port;
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);

    for (int i = 0; i < total_probe; i++)
    {

        if (sendto(socket_data->sockfd, NULL, 0, 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
        {
            perror("UDP PACKET SEND ERROR");
            return -1;
        }
        gettimeofday(&ptime[i].send_time, NULL);
        dest_port += 1;
    }
    return 1;
}

