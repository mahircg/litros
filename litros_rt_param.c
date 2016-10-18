#include <stdio.h>
#include "litros_rt_param.h"

void print_rt_params(struct rt_node_t *params) {
    printf("task_id:%s\t\nsched_type:%s\t\nscheduler:%s\t\nres_id:%d\t\n"
    "partition:%d\t\npriority:%d\t\nperiod:%.3f\t\nbudget:.%3f\t\n"
    "deadline::%.3f\t\noffset:%.3f\t\ncreate_new:%d\t\n", params->task_id,
    params->sched_type, params->scheduler, params->res_id, params->partition,
    params->priority, params->period, params->budget, params->deadline,
    params->offset, params->create_new);
}
