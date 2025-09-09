#include <stdio.h>
#include "Traceroute_tool.h"
#define DOMAIN_NAME_SIZE 200
int hop = 1;
void getTrace(double ms1, double ms2, double ms3, char offender_ip1[], char offender_ip2[], char offender_ip3[])
{
    char domain[3][DOMAIN_NAME_SIZE];
    char ret1 = getDomainName(offender_ip1, domain[0], DOMAIN_NAME_SIZE);
    char ret2 = getDomainName(offender_ip2, domain[1], DOMAIN_NAME_SIZE);
    char ret3 = getDomainName(offender_ip3, domain[2], DOMAIN_NAME_SIZE);
    printf("%d: ", hop++);
    (ms1 < 0) ? (printf("*  ")) : (printf("[%s](%s) %.3lf ms  ", ((ret1 < 0) ? "*" : domain[0]), offender_ip1, ms1));
    (ms2 < 0) ? (printf("*  ")) : (printf("[%s](%s) %.3lf ms  ", ((ret2 < 0) ? "*" : domain[1]), offender_ip2, ms2));
    (ms3 < 0) ? (printf("*  ")) : (printf("[%s](%s) %.3lf ms  ", ((ret3 < 0) ? "*" : domain[2]), offender_ip3, ms3));
    printf("\n");
}

int main()
{
    TraceIn_t *trace_data = configureTrace();
    strcpy(trace_data->des_ip, "57.144.160.1");
    trace_data->des_port = 53;
    trace_data->max_hop = 30;
    trace_data->timeout = 2;
    trace_data->callback = getTrace;
    int ret = startTrace();
    if (ret < 0)
        printf("Error\n");
    printf("Trace End\n");
    return 0;
}