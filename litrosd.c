#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <sys/queue.h>
#include <dirent.h>
#include <libgen.h>


#include "cJSON.h"
#include "common.h"
#include "litmus.h"
#include "litros_rt_param.h"

#define MAX_CONFIG_LEN 1024
#define RETRY_COUNT 50

#define CALL( exp ) do { \
	int ret; \
    ret = exp; \
    if (ret != 0) {\
        syslog(LOG_ALERT, "%s failed: %m\n", #exp);\
        return ret; \
    } \
    else { \
        syslog(LOG_WARNING, "%s ok.\n", #exp); \
	} \
} while (0)

#define CALL_ASSIGNMENT( exp ) do { \
    int ret; \
    ret = exp; \
    if (ret < 0) {\
        syslog(LOG_ALERT, "%s failed: %m\n", #exp);\
        syslog(LOG_ERR, "Error: %s", strerror(errno));\
        return ret; \
    }\
    else { \
        syslog(LOG_WARNING, "%s ok.\n", #exp); \
	} \
} while (0)

/** This macro assumes there is an integer variable ret and struct rt_status
  * defined in the current scope.
  */

#define CALL_LITMUS( exp ) do { \
    ret = exp; \
    if (ret < 0) { \
        syslog(LOG_WARNING, "%s failed: tid: %d, res_id: %d, task_id:%s", \
        #exp, rt_status->pid, rt_status->node->res_id, \
        rt_status->node->task_id); \
        syslog(LOG_ERR, "Error: %s", strerror(errno));\
        return ret; \
    } \
    else { \
        syslog(LOG_WARNING, "%s succeeded: tid: %d, res_id: %d, task_id:%s", \
        #exp, rt_status->pid, rt_status->node->res_id, \
        rt_status->node->task_id); \
    } \
} while(0)



static volatile bool need_exit = false;

struct litros_global_t {
    pthread_mutex_t *mutex;
    const char *directory;
    LIST_HEAD(listhead, rt_node_status_t) head;
};

struct litros_thread_local_t {
        int event_fd;
};

int parse_and_insert(const char * filename, const char *filepath);

struct rt_node_status_t *get_node_by_task_id(const char *task_id);
struct rt_node_status_t *get_node_by_pid(pid_t pid);

struct litros_global_t *global;

const char *usage_msg = 
    "Usage: litrosd OPTIONS\n"
    "Options:\n"
    "\t-d:\tFolder where node configuration files and metadata are stored\n";

static void usage(char *error) {
    if (error)
        fprintf(stderr, "Error: %s\n\n", error);
    else {
        fprintf(stderr, "rtspin: simulate a periodic CPU-bound "
                        "real-time task\n\n");
    }
    fprintf(stderr, "%s", usage_msg);
    exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}


/** Functions related to netlink connector are taken from
 *  http://bewareofgeek.livejournal.com/2945.html
 */
 
/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int nl_connect()
{
    int rc;
    int nl_sock;
    struct sockaddr_nl sa_nl;

    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket");
        return -1;
    }

    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
    if (rc == -1) {
        perror("bind");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

/*
 * subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sock, bool enable)
{
    int rc;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
    if (rc == -1) {
        perror("netlink send");
        return -1;
    }

    return 0;
}

static const char *get_process_name_by_pid(const int pid)                       
{
    FILE *f;
    static char name[1024];
    sprintf(name, "/proc/%d/cmdline", pid);
    f = fopen(name, "r");
    if (f) {
        size_t size;
        size = fread(name, sizeof(char), 1024, f);
        if(size>0) {
            if (name[size-1] == '\n')
                name[size-1] = '\0';
        }
        fclose(f);
        return basename(name);
    }
    else {
        fclose(f);
        return NULL;
    }
    
}

static const char *get_thread_type_by_tid(const int tgid, const int tid) 
{
    FILE *f;
    static char filename[1024];
    static char thread_name[16];
    sprintf(filename, "/proc/%d/task/%d/comm", tgid, tid);
    f = fopen(filename, "r");
    if (f) {
        size_t size;
        size = fread(thread_name, sizeof(char), 16, f);
        if(size>0) {
            if (thread_name[size-1] == '\n')
                thread_name[size-1] = '\0';
        }
        fclose(f);
        return thread_name;
    }
    else {
        fclose(f);
        return NULL;
    }

}

int create_reservation(struct rt_node_t *rt_node) 
{
    static struct reservation_config config;
    int ret = 0;
    config.id = rt_node->res_id;
    config.cpu = rt_node->partition;
    config.priority = rt_node->priority;
    syslog(LOG_WARNING, "trying to create R%d", rt_node->res_id);

    switch (rt_node->res_type) {
        case PERIODIC_POLLING:
        case SPORADIC_POLLING:
        case SOFT_POLLING:
            config.polling_params.budget = ms2ns(rt_node->budget);
            config.polling_params.period = ms2ns(rt_node->period);
            config.polling_params.offset = ms2ns(rt_node->offset);
            config.polling_params.relative_deadline
                = ms2ns(rt_node->deadline);
            break;
        case SPORADIC_SERVER:
            config.sporadic_server_params.budget = ms2ns(rt_node->budget);
            config.sporadic_server_params.period = ms2ns(rt_node->period);
            break;
        case DEFERRABLE_SERVER:
            config.deferrable_server_params.budget = ms2ns(rt_node->budget);
            config.deferrable_server_params.period = ms2ns(rt_node->period);
            config.deferrable_server_params.offset = ms2ns(rt_node->offset);
            config.deferrable_server_params.relative_deadline
                = ms2ns(rt_node->deadline);
            break;
        case CONSTANT_BANDWIDTH_SERVER:
        case HARD_CONSTANT_BANDWIDTH_SERVER:
        case CASH_CBS:
        case FLEXIBLE_CBS:
        case SLASH_SERVER:
            config.cbs_params.budget = ms2ns(rt_node->budget);
            config.cbs_params.period = ms2ns(rt_node->period);
            break;
        default:
            ret = -1;
            break;
    }
    ret = reservation_create(rt_node->res_type, &config);
    return ret;
}

int attach_node(struct rt_node_status_t *rt_status, pid_t tid)
{
    struct rt_task param;
    struct rt_node_t *rt_node = rt_status->node;
    struct sched_param linux_param;
	int ret;

    CALL_LITMUS( be_migrate_thread_to_cpu(tid, rt_node->partition) );

    init_rt_task_param(&param);
    /* dummy values */ 
    param.exec_cost = ms2ns(100);
    param.period = ms2ns(100);
    /* specify reservation as "virtual" CPU */
    param.cpu = rt_node->res_id;

    CALL_LITMUS( set_rt_task_param(tid, &param) );

    linux_param.sched_priority = 0;

    CALL( sched_setscheduler(tid, SCHED_LITMUS, &linux_param) );
	return 0;
}

void thread_cleanup(void *args) {
    struct litros_thread_local_t *local = (struct litros_thread_local_t*)args;

    pthread_mutex_unlock(global->mutex);
    close(local->event_fd);
}

void *check_file_changes(__attribute__ ((unused)) void *args)
{
    int event_fd;
    int wd;
    struct litros_thread_local_t local;
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    char *ptr;
    int len;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    memset(&local, 0, sizeof(struct litros_thread_local_t));

    event_fd = inotify_init();
    if (event_fd < 0) {
        syslog(LOG_WARNING, "inotify_init() failed. litrosd will not detect"
        "changes in configuration file directory");
        pthread_exit(NULL);
    }

    local.event_fd = event_fd;

    pthread_cleanup_push(thread_cleanup, &local);

    wd = inotify_add_watch(event_fd, global->directory,
                IN_CREATE | IN_DELETE | IN_MODIFY);

    if (wd < 0) {
        syslog(LOG_WARNING, "inotify_add_watch() failed. litrosd will not detect"
        " changes in configuration file directory");
        pthread_exit(NULL);
    }
    
    while (!need_exit) {
        len = read(event_fd, buf, sizeof(buf));
        if (len == -1) { 
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "inotify_event read error");
        }
        /** Acquire the mutex, check if a file is modified and reflect the
         *  changes if necessary.
         */
        for (ptr = buf; ptr < buf + len; 
            ptr += sizeof(struct inotify_event) + event->len) {

            event = (const struct inotify_event *) ptr;
            if (event->mask & IN_CREATE) {
                syslog(LOG_WARNING, "File %s created. Trying to"
                " parse and add to node list", event->name);
                parse_and_insert(event->name, global->directory);
            }
            if (event->mask & IN_DELETE)
                syslog(LOG_WARNING, "IN_DELETE: %s", event->name);
            if (event->mask & IN_MODIFY)
                syslog(LOG_WARNING, "IN_MODIFY: %s", event->name);
        }
    }
    /**
     * Every cleanup_push must be paired with a cleanup_pop
     * Otherwise, gcc keeps emitting esoteric warnings!
     */
    pthread_cleanup_pop(1);
    return NULL;
}

int switch_to_rt(pid_t pid, const char *thread_name)
{
    /** use a hash table or something since this operation is
     *  on the critical path and any further ways to avoid
     *  O(N) list traversal will improve the performance
     */
    const char *process_name;
    int ret;
    struct rt_node_status_t *rt_status;

    if (!thread_name)
        process_name = get_process_name_by_pid(pid);
    else
        process_name = thread_name;

    rt_status = get_node_by_task_id(process_name);
    if (rt_status) {
        if (rt_status->is_rt) {
            syslog(LOG_WARNING, "ROS node %s is already running!",
            process_name);
            return -1;
        }
        else {
            syslog(LOG_WARNING, "ROS node %s has been started with PID %d",
                process_name, pid) ;
			pthread_mutex_lock(global->mutex);
			rt_status->pid = pid;
			pthread_mutex_unlock(global->mutex);
            /** If this is a thread, then switch its scheduling policy
              * to SCHED_NORMAL first. This is necessary since reservation
              * parameters and scheduling policy of a thread is inherited
              * from the process that created the thread. By
              */
            if (thread_name)
                CALL_LITMUS( task_mode_with_pid(BACKGROUND_TASK, pid) );
            CALL_LITMUS( create_reservation(rt_status->node) );
            CALL_LITMUS( attach_node(rt_status, pid) );
            CALL_LITMUS( init_litmus() );
			pthread_mutex_lock(global->mutex);
            rt_status->is_rt = 1;
            pthread_mutex_unlock(global->mutex);
            return 0;
        }
    }
    else
        return ESRCH;
}

int switch_to_bg(pid_t pid)
{
    struct rt_node_status_t *rt_status;
    struct rt_node_t *rt_node;
    int ret;
    int i = 0;

    rt_status = get_node_by_pid(pid);
    if (rt_status) {
        rt_node = rt_status->node;
        pthread_mutex_lock(global->mutex);
        rt_status->pid = 0;
        rt_status->is_rt = 0;
        pthread_mutex_unlock(global->mutex);
        syslog(LOG_WARNING, "ROS node %s with PID %d has been terminated",
            rt_status->node->task_id, pid);
        do {
            ret = reservation_destroy(rt_node->res_id, rt_node->partition);
            if (i++ > RETRY_COUNT)
                break;
        } while(ret != 0);

        if (ret == 0)
            syslog(LOG_WARNING, "removed reservation %d", rt_node->res_id);
        else
            syslog(LOG_WARNING, "could not remove reservation %d",
            rt_node->res_id);
        return ret;
    }
    return ESRCH;
}
static int handle_proc_ev(int nl_sock)
{
    int rc;
    pid_t p_pid;
	pid_t t_gid;
    int ret;
	struct rt_node_status_t * tmp;
    char thread_name[64];
    const char *thread_type;

    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    while (!need_exit) {
        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) {
            return 0;
        } else if (rc == -1) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "netlink recv");
            return -1;
        }
        switch (nlcn_msg.proc_ev.what) {
            case PROC_EVENT_NONE:
                syslog(LOG_WARNING, "set mcast listen ok\n");
                break;
			case PROC_EVENT_FORK:
				t_gid = nlcn_msg.proc_ev.event_data.fork.child_tgid;
				p_pid = nlcn_msg.proc_ev.event_data.fork.child_pid;
				tmp = get_node_by_pid(t_gid);
				if (tmp) {
                    thread_type = get_thread_type_by_tid(t_gid, p_pid);
                    sprintf(thread_name, "%s_%s", tmp->node->task_id,
                        thread_type);
                    syslog(LOG_WARNING, "%s forked %s with TID %d", tmp->node->task_id,
                    thread_name, p_pid);
                    ret = switch_to_rt(p_pid, thread_name);
                    if (ret != ESRCH) {
                        if (ret == 0)
                            syslog(LOG_WARNING, "switched to RT mode");
                        else
                            syslog(LOG_ERR, "could not switch to RT mode");
                    }
                    else
                        syslog(LOG_WARNING, "%s does not have configuration"
                            " file. It will be executed on reservation of %s",
                            thread_name, tmp->node->task_id);
				}
			    break;
            case PROC_EVENT_EXEC:
                p_pid = nlcn_msg.proc_ev.event_data.exec.process_pid;
                ret = switch_to_rt(p_pid, NULL);
                if (ret != ESRCH) {
                    if (ret == 0)
                        syslog(LOG_WARNING, "switched to RT mode");
                    else
                        syslog(LOG_ERR, "could not switch to RT mode");
                }
                break;
            case PROC_EVENT_EXIT:
                /** By default, ROS kills the previous node instance if the
                  * same node is started twice. It should be taken 
                  * care of somehow
                  */
                p_pid = nlcn_msg.proc_ev.event_data.exec.process_pid;
                ret = switch_to_bg(p_pid);
                if (ret != ESRCH) {
                    if (ret == 0)
                        syslog(LOG_WARNING, "ROS node is terminated successfully");
                    else
                        syslog(LOG_ERR, "ROS node could not be terminated!");
                }
                break;
            default:
                /* Do not log all messages, at least for now */
                break;
        }
    }
    return 0;
}

static void on_shutdown(int sig)
{
    (void)sig;
    syslog(LOG_WARNING, "shutting down");
    need_exit = true;
}

int litros_init(void)
{
    pid_t sid;
    struct sigaction sig;

    umask(0);

    openlog("litrosd", LOG_CONS | LOG_PID, LOG_DAEMON);

    CALL_ASSIGNMENT( (sid = setsid()) );

    CALL( chdir("/") );

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    memset(&sig, 0, sizeof(struct sigaction));
    sig.sa_handler = on_shutdown;

    sigaction(SIGINT, &sig, NULL);
    sigaction(SIGTERM, &sig, NULL);
	return 0;
}

int check_params(struct rt_node_t *rt_node)
{
    if (rt_node->res_type == -1)
        return -1;

    if (rt_node->period <= 0 || rt_node->budget <= 0
            || (rt_node->budget >= rt_node->period) )
        return -1;

    if (rt_node->partition < 0)
        return -1;

    return 0;
}
int parse_params(const char *args, struct rt_node_t *params)
{
    cJSON *root;
    static int tmp_int;
    static double tmp_double;

    root = cJSON_Parse(args);
    if (!root)
        return -1;    

    tmp_double = cJSON_GetObjectItem(root, "period")->valuedouble;
    params->period = tmp_double;
    tmp_double = cJSON_GetObjectItem(root, "budget")->valuedouble;
    params->budget = tmp_double;
    tmp_double = cJSON_GetObjectItem(root, "deadline")->valuedouble;
    params->deadline = tmp_double;
    tmp_double = cJSON_GetObjectItem(root, "offset")->valuedouble;
    params->offset = tmp_double;


    tmp_int = cJSON_GetObjectItem(root, "priority")->valueint;
    params->priority = tmp_int;
    tmp_int = cJSON_GetObjectItem(root, "partition")->valueint;
    params->partition = tmp_int;
    tmp_int = cJSON_GetObjectItem(root, "res_id")->valueint;
    params->res_id = tmp_int;

    strcpy(params->res_str, cJSON_GetObjectItem(root, "res_str")->valuestring);
    strcpy(params->task_id, cJSON_GetObjectItem(root, "task_id")->valuestring);
    
    params->res_type = parse_reservation_type(params->res_str);
    return 0;
}

struct rt_node_status_t *get_node_by_task_id(const char *task_id)
{

    struct rt_node_status_t *it;
    pthread_mutex_lock(global->mutex);
    for (it = global->head.lh_first; it != NULL; it = it->list.le_next) {
        if (strcmp(it->node->task_id, task_id) == 0) {
            pthread_mutex_unlock(global->mutex);
            return it;
        }
    }
    pthread_mutex_unlock(global->mutex);
    return NULL;
}

struct rt_node_status_t *get_node_by_pid(pid_t pid)
{

    struct rt_node_status_t *it;
    pthread_mutex_lock(global->mutex);
    for (it = global->head.lh_first; it != NULL; it = it->list.le_next) {
        if (it->pid == pid) {
            pthread_mutex_unlock(global->mutex);
            return it;
        }
    }
    pthread_mutex_unlock(global->mutex);
    return NULL;
}

int remove_on_node_exit(pid_t pid)
{
    struct rt_node_status_t *it;
    int ret = -1;
    syslog(LOG_WARNING, "trying to remove the reservation of PID %d", pid);
    for (it = global->head.lh_first; it != NULL; it = it->list.le_next) {
        if (it->pid == pid && it->is_rt == 1) {
            ret = reservation_destroy(it->node->res_id, it->node->partition);
            if (ret == -1)
                syslog(LOG_WARNING, "could not remove reservation %d on cpu %d",
                it->node->res_id, it->node->partition);
            else
                 syslog(LOG_WARNING, "removed reservation %d on cpu %d",
                 it->node->res_id, it->node->partition);
            LIST_REMOVE(it, list);
            free(it->node);
            free(it);
            return ret;
        }
    }

    return ret; 
}
int parse_and_insert(const char * filename, const char *filepath)
{
    int ret;
    struct rt_node_status_t *tmp_status;
    struct rt_node_status_t *it;


    char config_str[MAX_CONFIG_LEN] = "";
    FILE *config_fp = NULL;
    size_t config_len;

    syslog(LOG_WARNING, "reading configuration from %s", filepath);
    config_fp = fopen(filepath, "r");
    config_len = fread(config_str, sizeof(char), MAX_CONFIG_LEN, config_fp);
    if (config_len == 0) {
        syslog(LOG_WARNING, "empty file %s", filename);
        ret = -1;
    }
    else{
        config_str[++config_len] = '\0';
        tmp_status = malloc(sizeof(struct rt_node_status_t));
        tmp_status->node = malloc(sizeof(struct rt_node_t));
        tmp_status->is_rt = 0;
        tmp_status->pid = 0;
        ret = parse_params(config_str, tmp_status->node);
        if (ret != 0)
            syslog(LOG_ERR, "could not parse JSON file %s", filename);
        else {
            syslog(LOG_WARNING, "parsed JSON file %s", filename);
            syslog(LOG_WARNING, "node parameters:\n%s", 
                    param_to_str(tmp_status->node));
            for (it = global->head.lh_first; it != NULL; it = it->list.le_next) {
                if (strcmp(it->node->task_id, tmp_status->node->task_id) == 0) {
                    syslog(LOG_WARNING, "Task %s in file %s is already added"
                    " ,skipping!", it->node->task_id, filename);
                    goto err;
                }
                else if ( (it->node->res_id == tmp_status->node->res_id) &&
                    (it->node->partition == tmp_status->node->partition) ) {
                    syslog(LOG_WARNING, "res_id %d in file %s is already added"
                    " ,skipping!", it->node->res_id, filename);
                    goto err;
                }
            }
            syslog(LOG_WARNING, "checking RT parameters");
            ret = check_params(tmp_status->node);
            if (ret == 0) {
                syslog(LOG_WARNING, "RT parameters are valid");
                pthread_mutex_lock(global->mutex);
                LIST_INSERT_HEAD(&global->head, tmp_status, list);
                pthread_mutex_unlock(global->mutex);
            }
            else
                goto err;
        }
    }
    return ret;

err:    
    syslog(LOG_ERR, "RT parameters are invalid");
    free(tmp_status->node);
    free(tmp_status);
    return -1;
}


#define OPTSTR "d:"

int main(int argc, char **argv)
{
    pid_t pid;
    pthread_t io_tid;

    int nl_sock;
    int ret = EXIT_SUCCESS;
    int opt;

    char directory[128] = "";
    size_t dir_len;
    DIR *dp = NULL;
    struct dirent *ep = NULL;
    char config_filename[128] = "";
    struct rt_node_status_t *rt_node_status;

    while ((opt = getopt(argc, argv, OPTSTR)) != -1) {
        switch (opt) {
            case 'd':
                strcpy(directory, optarg);
                break;
            default:
                usage("bad argument");
                break;
        }
    }

    if (strlen(directory) == 0) {
        usage("directory must be specified with -d");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    else if (pid > 0)
        exit(EXIT_SUCCESS);

    ret = litros_init();
	if (ret != 0) {
		syslog(LOG_WARNING, "litros_init() failed");
		return ret;
	}

    dp = opendir(directory);
    if (!dp) {
        syslog(LOG_ERR, "opendir(): %s", strerror(errno));
        closelog();
        exit(EXIT_FAILURE);
    }

    dir_len = strlen(directory);
    if (directory[dir_len - 1] != '/')
        strcat(directory, "/");


    global = malloc(sizeof(struct litros_global_t));
    global->directory = directory;
    global->mutex = malloc(sizeof(pthread_mutex_t));
    CALL( pthread_mutex_init(global->mutex, NULL) );
    LIST_INIT(&global->head);

    while ( (ep = readdir(dp)) ) {
        if (ep->d_type != DT_REG)
            continue;
        sprintf(config_filename, "%s%s", directory, ep->d_name);
        ret = parse_and_insert(ep->d_name, config_filename);
        if (ret == 0)
            syslog(LOG_WARNING, "config inserted into the list");
        else
            syslog(LOG_WARNING, "config could not be inserted into list");
    }
    if (errno == EBADF)
        syslog(LOG_ERR, "readdir(): %s", strerror(errno));

    pthread_create(&io_tid, NULL, check_file_changes, NULL);

    CALL_ASSIGNMENT( nl_sock = nl_connect() );
    ret = set_proc_ev_listen(nl_sock, true);
    if (ret != 0) {
        ret = EXIT_FAILURE;
        goto out;
    }
    ret = handle_proc_ev(nl_sock);
    if (ret != 0) {
        ret = EXIT_FAILURE;
        goto out;
    }

    while (global->head.lh_first != NULL) {
        rt_node_status = global->head.lh_first;
        LIST_REMOVE(rt_node_status, list);
        free(rt_node_status->node);
        free(rt_node_status);

    }
    set_proc_ev_listen(nl_sock, false);
    free(global);

out:
    closelog();
    close(nl_sock);
    return ret;
}
