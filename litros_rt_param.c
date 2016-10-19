#include <stdio.h>
#include "litros_rt_param.h"

const char *param_to_str(struct rt_node_t *params) {
    static char buf[256];
    sprintf(buf, "task_id:%s\t\nres_id:%d\t\nres_str:%s\t\n"
    "partition:%d\t\npriority:%d\t\nperiod:%.3f\t\nbudget:%.3f\t\n"
    "deadline::%.3f\t\noffset:%.3f\t\n", params->task_id, params->res_id, 
    params->res_str, params->partition, params->priority, params->period, 
    params->budget, params->deadline, params->offset);

    return buf;
}
