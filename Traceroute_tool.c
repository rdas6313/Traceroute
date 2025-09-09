#include "Traceroute_tool.h"

SocketIn_t *socket_data;

int8_t getDomainName(char *ip, char *domain, uint32_t domainSize)
{
    struct sockaddr_in addr = {0};
    memset(domain, 0, sizeof(*domain));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);
    int32_t ret = getnameinfo((struct sockaddr *)&addr, sizeof(addr), domain, domainSize, NULL, 0, NI_NAMEREQD);
#ifdef DEBUG
    printf("DOMAIN RESOLVER RETURN: %d\n", ret);
#endif
    if (ret != 0)
    {
#ifdef DEBUG
        fprintf(stderr, "getnameinfo: %s\n", gai_strerror(ret));
#endif
        return -1;
    }
#ifdef DEBUG
    printf("DOMAIN NAME: %s\n", domain);
#endif
    return 1;
}

void release_resource(void)
{
    if (socket_data == NULL)
        return;
    close(socket_data->usock_fd);
    close(socket_data->isock_fd);
#ifdef DEBUG
    printf("Socket closed Successfully!\n");
#endif
    if (socket_data->trace_data)
        free(socket_data->trace_data);
    free(socket_data);
#ifdef DEBUG
    printf("Memory Deallocated Successfully!\n");
#endif
}

uint8_t checkInputError()
{
    if (socket_data == NULL)
    {
        PRINT_ERROR("SOCKETDATA NOT INTIALIZED");
        return -1;
    }
    else if (socket_data->trace_data == NULL)
    {
        PRINT_ERROR("TRACEDATA NOT INITIALIZED");
        return -1;
    }
    else if (socket_data->trace_data->timeout == 0)
        socket_data->trace_data->timeout = DEFAULT_RECV_TIMEOUT;
    else if (socket_data->trace_data->des_port == 0)
        socket_data->trace_data->des_port = DEFAULT_DEST_PORT;
    else if (socket_data->trace_data->max_hop == 0)
        socket_data->trace_data->max_hop = DEFAULT_MAX_HOP;
    else if (socket_data->trace_data->callback == NULL)
    {
        PRINT_ERROR("CALLBACK ERROR");
        return -1;
    }
    else if (strcmp(socket_data->trace_data->des_ip, "") == 0)
    {
        PRINT_ERROR("DESTINATION IP ERROR");
        return -1;
    }
    return 1;
}

int8_t socketConfigure()
{
    if (socket_data == NULL)
    {
        PRINT_ERROR("SOCKETDATA: NOT INTIALIZED");
        return -1;
    }
    else if (socket_data->trace_data == NULL)
    {
        PRINT_ERROR("TRACEDATA: NOT INTIALIZED");
        return -1;
    }

    // creating socket
    socket_data->usock_fd = socket(AF_INET, SOCK_DGRAM, 0);

#ifdef DEBUG
    printf("Sock Fd: %d\n", socket_data->usock_fd);
#endif

    if (socket_data->usock_fd < 0)
    {
        PRINT_ERROR("UDP SOCKET INTIALIZATION ERROR");
        return -1;
    }
    // initialization for socket address
    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = INADDR_ANY;
    myaddr.sin_port = htons(MY_PORT);

    // binding traceroute to a specific ip/port
    if (bind(socket_data->usock_fd, (const struct sockaddr *)&myaddr, sizeof(myaddr)) < 0)
    {
        PRINT_ERROR("BIND FAILED");
        return -1;
    }

    // create raw socket for icmp
    socket_data->isock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_data->isock_fd < 0)
    {
        PRINT_ERROR("RAW SOCKET INTIALIZATION ERROR");
        return -1;
    }

    // set Timeout to 2-3 sec
    struct timeval tv;
    tv.tv_sec = 2; // 2-second timeout
    tv.tv_usec = 0;
    if (setsockopt(socket_data->isock_fd, SOL_SOCKET, SO_RCVTIMEO, (const void *)&tv, sizeof(tv)) < 0)
    {
        PRINT_ERROR("RECV TIME SET ERROR");
        return -1;
    }
    return 1;
}

int8_t sendProbeMsg(ProbeMsg_t *pmsg, int total_probe)
{

    const char *dest_ip = socket_data->trace_data->des_ip;
    uint16_t dest_port = socket_data->trace_data->des_port;
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
    char dummy_data[256] = {0};

    for (int i = 0; i < total_probe; i++)
    {
        dest_addr.sin_port = htons(dest_port);
        if (sendto(socket_data->usock_fd, dummy_data, 256, 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
        {
            PRINT_ERROR("UDP PACKET SEND ERROR");
            return -1;
        }
        gettimeofday(&pmsg[i].send_time, NULL);
        dest_port += 1;
    }
    return 1;
}

int8_t changeTTL(uint32_t ttl)
{
    if (setsockopt(socket_data->usock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        PRINT_ERROR("TTL SETTING FAILED");
        return -1;
    }
#ifdef DEBUG

    unsigned int ttl_test;
    socklen_t size = sizeof(ttl_test);
    getsockopt(socket_data->usock_fd, IPPROTO_IP, IP_TTL, &ttl_test, &size);
    printf("Current TTL: %d\n", ttl_test);

#endif
    return 1;
}

int8_t captureICMP(ProbeMsg_t *pmsg, uint8_t total_probe)
{
    char buffer[BUFFER_SIZE] = {0};
    struct sockaddr_in addr = {0};
    socklen_t size = 0;
    for (int i = 0; i < total_probe; i++)
    {
        memset(pmsg[i].offender_ip, 0, sizeof(pmsg[i].offender_ip));
        pmsg[i].icmp_error = 0;
    }

    for (int i = 0; i < total_probe; i++)
    {
        memset(buffer, 0, sizeof(buffer));
        memset(&addr, 0, sizeof(addr));

        if (recvfrom(socket_data->isock_fd, buffer, BUFFER_SIZE, 0, NULL, &size) < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
#ifdef DEBUG
                printf("NO ICMP RECEIVED TILL TIMEOUT\n");
#endif
            }
            else
                PRINT_ERROR("RECV FROM ERROR");
            return 1;
        }

        struct iphdr *iphdr = (struct iphdr *)buffer;
        uint32_t ip_header_len = iphdr->ihl * 4;
        struct icmphdr *icmphdr = (struct icmphdr *)(buffer + ip_header_len);

        struct iphdr *icmp_iphdr = (struct iphdr *)((char *)icmphdr + sizeof(*icmphdr));
        ip_header_len = icmp_iphdr->ihl * 4;
        struct udphdr *udphdr = (struct udphdr *)((char *)icmp_iphdr + ip_header_len);
        uint16_t dest_port = ntohs(udphdr->uh_dport);

        int index = dest_port - socket_data->trace_data->des_port;
#ifdef DEBUG
        printf("Received Udp Destination port: %d\n", dest_port);
        printf("User selected Destination port: %d\n", socket_data->trace_data->des_port);
#endif
        if (index < 0 || index >= total_probe)
        {
            PRINT_ERROR("Index Error");
            continue;
        }

        gettimeofday(&pmsg[index].recv_time, NULL);

        pmsg[index].icmp_error = ICMP_UNREACHABLE;
        if (icmphdr->type == TYPE_TTL_EXPIRED && icmphdr->code == CODE_TTL_EXPIRED)
        {
            pmsg[index].icmp_error = ICMP_TTL_EXPIRED;
        }

        addr.sin_addr.s_addr = iphdr->saddr;
        inet_ntop(AF_INET, &addr.sin_addr, pmsg[index].offender_ip, sizeof(pmsg[index].offender_ip));

#ifdef DEBUG
        printf("Pmsg index: %d\n", index);
        printf("ICMP ERROR TYPE: %d\n", icmphdr->type);
        printf("ICMP ERROR CODE: %d\n", icmphdr->code);
        printf("Offender ip: %s\n", pmsg[index].offender_ip);
#endif
    }
}

int8_t initiate_callback(ProbeMsg_t *probeMsg, uint8_t total_probe)
{

    double ms[3] = {0};
    uint8_t stop = 0;
    for (int i = 0; i < total_probe; i++)
    {
        // calculating Round trip time
        ms[i] = ((probeMsg[i].recv_time.tv_sec - probeMsg[i].send_time.tv_sec) * 1000) + ((double)(probeMsg[i].recv_time.tv_usec - probeMsg[i].send_time.tv_usec) / 1000);
        // if we get ICMP Unreachable then we stop hoping more
        stop = (probeMsg[i].icmp_error == ICMP_UNREACHABLE) ? 1 : 0;
    }
    // calling callback to send probe data to UI
    socket_data->trace_data->callback(ms[0], ms[1], ms[2], probeMsg[0].offender_ip, probeMsg[1].offender_ip, probeMsg[2].offender_ip);
    return stop;
}

int8_t start_tracing()
{
    uint8_t max_hop = socket_data->trace_data->max_hop;
    ProbeMsg_t probeMsg[3];

    for (int i = 0; i < max_hop; i++)
    {
        memset(probeMsg, 0, sizeof(probeMsg)); // initializing probetime with 0
        if (changeTTL(i + 1) < 0)              // changing TTL to 0,1,2,3....so on
            return -1;
        if (sendProbeMsg(probeMsg, 3) < 0) // sending 3 probe msg for each TTL
            return -1;

        if (captureICMP(probeMsg, 3) < 0) // capure 3 probe icmp for each TTL
            return -1;

        if (initiate_callback(probeMsg, 3) > 0) // returning value to UI and if initiate_callback return > 0 then if got destination or destination not reachable so, stop here
            break;
#ifdef DEBUG
        printf("*********************************************\n\n");
#endif
    }
    return 1;
}

int8_t startTrace(void) // UI API Function
{
    int8_t error = 0;

#ifdef DEBUG
    printf("DEBUG MODE ON!\n");
    if (checkInputError() < 0)
    {
        error = -1;
    }
    else if (socketConfigure() < 0)
    {
        error = -1;
        printf("SockFd: %d", socket_data->usock_fd);
    }
    else if (start_tracing() < 0)
    {
        error = -1;
    }
#else
    if (checkInputError() < 0 || (socketConfigure() < 0) || (start_tracing() < 0))
        error = -1;
#endif
    release_resource();
    return error;
}

TraceIn_t *configureTrace(void) // UI API Function
{

    if (socket_data == NULL)
    {
        socket_data = (SocketIn_t *)malloc(sizeof(SocketIn_t));
        socket_data->trace_data = (TraceIn_t *)malloc(sizeof(TraceIn_t));
    }
    memset(socket_data->trace_data, 0, sizeof(*socket_data->trace_data));
    socket_data->usock_fd = 0;
    socket_data->isock_fd = 0;
    return socket_data->trace_data;
}
