#ifndef LITROS_RT_PARAM_H
#define LITROS_RT_PARAM_H

#include <stdio.h>
#include <sys/queue.h>
#include <sys/types.h>
#include "common.h"



struct rt_node_t{
    char res_str[64];
    char task_id[64];
	int res_type;
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
    pid_t pid;
    LIST_ENTRY(rt_node_status_t) list;
};

const char *param_to_str(struct rt_node_t *params);

	
#endif
