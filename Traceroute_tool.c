#include "Traceroute_tool.h"

SocketIn_t *socket_data;

void release_resource(void)
{
    if (socket_data == NULL)
        return;
    if (socket_data->trace_data)
        free(socket_data->trace_data);
    free(socket_data);
}

uint8_t checkInputError()
{
    if (socket_data == NULL)
    {
        perror("SOCKETDATA NOT INTIALIZED");
        return -1;
    }
    else if (socket_data->trace_data == NULL)
    {
        perror("TRACEDATA NOT INITIALIZED");
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
        perror("CALLBACK ERROR");
        return -1;
    }
    else if (strcmp(socket_data->trace_data->des_ip, "") == 0)
    {
        perror("DESTINATION IP ERROR");
        return -1;
    }
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

int8_t sendProbeMsg(ProbeMsg_t *pmsg, int total_probe)
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
        gettimeofday(&pmsg[i].send_time, NULL);
        dest_port += 1;
    }
    return 1;
}

int8_t changeTTL(int8_t ttl)
{
    if (setsockopt(socket_data->sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        perror("TTL SETTING FAILED");
        return -1;
    }
    return 1;
}

int8_t captureICMP(ProbeMsg_t *pmsg, uint8_t total_probe)
{
    char buffer[BUFFER_SIZE];         // store data of ICMP
    char control_buffer[BUFFER_SIZE]; // store control msgs
    struct iovec iov;
    struct msghdr msg;

    // initializing buffer
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    // initializing special structure msg which will capture icmp and icmp data
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buffer;
    msg.msg_controllen = sizeof(control_buffer);
    // add msg name also if needed

    for (int i = 0; i < total_probe; i++)
    {
        // initializing data buffer,control buffer and ip of router which will send icmp
        memset(buffer, 0, sizeof(buffer));
        memset(control_buffer, 0, sizeof(control_buffer));
        memset(pmsg[i].offender_ip, 0, sizeof(pmsg[i].offender_ip));

        // recving only Error Queue packets
        if (recvmsg(socket_data->sockfd, &msg, MSG_ERRQUEUE) < 0)
        { // if errno is EAGAIN or EWOULDBLOCK then Msg queue is empty and timeout happened
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 1;
            }
            else // otherwise some error happened, record it
            {
                perror("RECVMSG ERROR");
                return -1;
            }
        }

        // saving recv time of icmp.
        gettimeofday(&pmsg[i].recv_time, NULL);

        // Checking each control msg to get icmp error type,code and offender ip
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVERR)
            {
                struct sock_extended_err *error = (struct sock_extended_err *)CMSG_DATA(cmsg);
                struct sockaddr_in *offender_ip = (struct sockaddr_in *)SO_EE_OFFENDER(error);

                if (error == NULL || error->ee_origin != SO_EE_ORIGIN_ICMP)
                    continue;

                // if error type is TTL expired and code TTL expired then mark this probe as ICMP TTL Expired
                if (error->ee_type == TYPE_TTL_EXPIRED && error->ee_code == CODE_TTL_EXPIRED)
                {
                    pmsg[i].icmp_error = ICMP_TTL_EXPIRED;
                }
                else // if any other icmp error will assume it is Destination not reachable and mark it as unreachable
                {
                    pmsg[i].icmp_error = ICMP_UNREACHABLE;
                }
                // if offender ip present record it by converting to human readable form.
                if (offender_ip != NULL)
                    inet_ntop(AF_INET, &offender_ip->sin_addr, pmsg[i].offender_ip, sizeof(pmsg[i].offender_ip));
            }
        }
    }
    return 1;
}

int8_t initiate_callback(ProbeMsg_t *probeMsg, uint8_t total_probe)
{

    uint8_t ms[3] = {0};
    uint8_t stop = 0;
    for (int i = 0; i < total_probe; i++)
    {
        // calculating Round trip time
        ms[i] = ((probeMsg[i].recv_time.tv_sec - probeMsg[i].send_time.tv_sec) * 1000) + ((probeMsg[i].recv_time.tv_usec - probeMsg[i].send_time.tv_usec) / 1000);
        // if we get ICMP Unreachable then we stop hoping more
        stop = (probeMsg[i].icmp_error == ICMP_UNREACHABLE) ? 1 : 0;
    }
    // calling callback to send probe data to UI
    socket_data->trace_data->callback(ms[0], ms[1], ms[2], probeMsg[0].offender_ip);
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
    }
    return 1;
}

int8_t startTrace(void) // UI API Function
{
    int8_t error = 0;
    if (checkInputError() < 0 || (socketConfigure < 0) || (start_tracing() < 0))
        error = -1;
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
    memset(socket_data, 0, sizeof(socket_data));
    return socket_data->trace_data;
}