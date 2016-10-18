#ifndef LITROS_RT_PARAM_H
#define LITROS_RT_PARAM_H

#include <stdio.h>
#include "litmus.h"


struct rt_node_t{
	const char* sched_type;
	const char* scheduler;
    const char* task_id;
	reservation_type_t res_type;
	int partition;
	uint32_t priority;
	double period;
	double budget;
	double deadline;
	double offset;
	int res_id;
	int create_new;
};

struct rt_node_status {
    struct rt_node_t *node;
    int is_rt;
};

void print_rt_params(struct rt_node_t *params);

	
#endif
