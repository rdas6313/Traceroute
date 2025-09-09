#include <stdio.h>
#include "Traceroute_tool.h"
#define DOMAIN_NAME_SIZE 200

int hop = 1;
void getTrace(double ms1, double ms2, double ms3, char offender_ip1[], char offender_ip2[], char offender_ip3[], char skip_dns)
{
    char domain[3][DOMAIN_NAME_SIZE], ret1 = -1, ret2 = -1, ret3 = -1;
    if (!skip_dns)
    {
        ret1 = getDomainName(offender_ip1, domain[0], DOMAIN_NAME_SIZE);
        ret2 = getDomainName(offender_ip2, domain[1], DOMAIN_NAME_SIZE);
        ret3 = getDomainName(offender_ip3, domain[2], DOMAIN_NAME_SIZE);
    }
    printf("%d: ", hop++);
    if (ms1 < 0)
    {
        printf(RED "*   " RESET);
    }
    else
    {
        if (ret1 >= 0)
            printf(GREEN "[%s]" RESET, domain[0]);
        printf(YELLOW "(%s)" RESET " %.3lf ms   ", offender_ip1, ms1);
    }
    if (ms2 < 0)
    {
        printf(RED "*   " RESET);
    }
    else
    {
        if (ret2 >= 0)
            printf(GREEN "[%s]" RESET, domain[1]);
        printf(YELLOW "(%s)" RESET " %.3lf ms   ", offender_ip2, ms2);
    }
    if (ms3 < 0)
    {
        printf(RED "*   " RESET);
    }
    else
    {
        if (ret3 >= 0)
            printf(GREEN "[%s]" RESET, domain[2]);
        printf(YELLOW "(%s)" RESET " %.3lf ms   ", offender_ip3, ms3);
    }
    printf("\n");
}

char is_valid_ip(const uint8_t *p)
{
    char ip[IP_ADDR_LEN] = {0};
    strcpy(ip, p);

    if (strcmp(ip, "") == 0)
        return 0;

    char *token = strtok((char *)ip, ".");
    char oct = 0;
    while (token != NULL)
    {
        oct += 1;
#ifdef DEBUG
        printf("%d octet: %s\n", oct, token);
#endif
        if (strtol(token, NULL, 10) == 0)
        {
            return 0;
        }
        token = strtok(NULL, ".");
    }
#ifdef DEBUG
    printf("Ip octet: %d\n", oct);
#endif
    if (oct != 4)
        return 0;

    return 1;
}

int main(int argc, char *argv[])
{
    int i;
    TraceIn_t *trace_data = configureTrace();
    memset(trace_data, 0, sizeof(*trace_data));
    for (i = 1; i < argc; i++)
    {

        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
        {
            trace_data->max_hop = strtol(argv[i + 1], NULL, 10);
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            trace_data->skip_dns = 1;
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {

            trace_data->des_port = strtol(argv[i + 1], NULL, 10);
        }
        else if (strcmp(argv[i], "-e") == 0)
        {
            trace_data->show_error = 1;
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            trace_data->timeout = strtol(argv[i + 1], NULL, 10);
        }
        else if (strlen(argv[i]) >= 7)
        {
            strcpy(trace_data->des_ip, argv[i]);
        }
    }
    trace_data->callback = getTrace;
    if (is_valid_ip(trace_data->des_ip) == 0)
    {
        printf("Input Error: Give valid ip!\n");
        return 0;
    }

#ifdef DEBUG
    printf("................................................\n");
    printf("Destination ip: %s\n", trace_data->des_ip);
    printf("Destination port: %d\n", trace_data->des_port);
    printf("Max hop: %d\n", trace_data->max_hop);
    printf("Timeout: %d\n", trace_data->timeout);
    printf("Error show: %d\n", trace_data->show_error);
    printf("Skip Dns: %d\n", trace_data->skip_dns);
    printf("................................................\n");
#endif

    printf("Tracing route to " YELLOW "%s\n\n" RESET, trace_data->des_ip);
    int ret = startTrace();
    if (ret < 0)
        printf(RED "Error: Some Error occured. For more information use -e option\n" RESET);

    return 0;
}