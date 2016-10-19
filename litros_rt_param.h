#ifndef LITROS_RT_PARAM_H
#define LITROS_RT_PARAM_H

#include <stdio.h>
#include <sys/queue.h>
#include "common.h"



struct rt_node_t{
    const char* res_str;
    const char* task_id;
	reservation_type_t res_type;
	int partition;
	int priority;
	double period;
	double budget;
	double deadline;
	double offset;
	int res_id;
};

struct rt_node_status_t {
    struct rt_node_t *node;
    int is_rt;
    LIST_ENTRY(rt_node_status) list;
};

const char *param_to_str(struct rt_node_t *params);

	
#endif
