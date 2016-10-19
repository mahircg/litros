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

#include "cJSON.h"
#include "common.h"
#include "litros_rt_param.h"

#define MAX_CONFIG_LEN 1024

#define CALL( exp ) do { \
        int ret; \
        ret = exp; \
        if (ret != 0) {\
            syslog(LOG_ALERT, "%s failed: %m\n", #exp);\
            closelog();\
            exit(EXIT_FAILURE);\
        }\
        else \
            syslog(LOG_WARNING, "%s ok.\n", #exp); \
    } while (0)

#define CALL_ASSIGNMENT( exp ) do { \
        int ret; \
        ret = exp; \
        if (ret < 0) {\
            syslog(LOG_ALERT, "%s failed: %m\n", #exp);\
            closelog();\
            exit(EXIT_FAILURE);\
        }\
        else \
            syslog(LOG_WARNING, "%s ok.\n", #exp); \
    } while (0)

static volatile bool need_exit = false;

struct litros_global_t {
    pthread_mutex_t *mutex;
    const char *directory;
    LIST_HEAD(listhead, rt_node_status_t) head;
};

struct litros_thread_local_t {
        struct litros_global_t *global;
        int event_fd;
};

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

static const char* get_process_name_by_pid(const int pid)                       
{
    FILE *f;
    char* name;

    name = malloc(sizeof(char) * 1024);
    if (name) {
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
        }
    }
    return name;
}

void thread_cleanup(void *args) {
    struct litros_thread_local_t *local = (struct litros_thread_local_t*)args;
    
    pthread_mutex_unlock(local->global->mutex);
    close(local->event_fd);
}

void *check_file_changes(void *args) 
{
    int event_fd;
    int wd;
    struct litros_global_t *global;
    struct litros_thread_local_t local;
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    char *ptr;
    int len;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    memset(&local, 0, sizeof(struct litros_thread_local_t));
    global = (struct litros_global_t*)args;

    event_fd = inotify_init();
    if (event_fd < 0) {
        syslog(LOG_WARNING, "inotify_init() failed. litrosd will not detect"
        "changes in configuration file directory");
        pthread_exit(NULL);
    }

    local.global = global;
    local.event_fd = event_fd;
    
    pthread_cleanup_push(thread_cleanup, &local);

    wd = inotify_add_watch(event_fd, global->directory,
                IN_CREATE | IN_DELETE | IN_MODIFY);

    if (wd < 0) {
        syslog(LOG_WARNING, "inotify_add_watch() failed. litrosd will not detect"
        " changes in configuration file directory");
        pthread_exit(NULL);
    }
    
    while (1) {
        len = read(event_fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            syslog(LOG_ERR, "inotify_event read error");
            continue;
        }

        for (ptr = buf; ptr < buf + len; 
            ptr += sizeof(struct inotify_event) + event->len) {

            event = (const struct inotify_event *) ptr;
            if (event->mask & IN_CREATE)
                syslog(LOG_WARNING, "IN_CREATE: %s", event->name);
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

static int handle_proc_ev(int nl_sock)
{
    int rc;
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
            /* shutdown? */
            return 0;
        } else if (rc == -1) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "netlink recv");
            return -1;
        }
        switch (nlcn_msg.proc_ev.what) {
            case PROC_EVENT_NONE:
                printf("set mcast listen ok\n");
                break;
            case PROC_EVENT_FORK:
                syslog(LOG_WARNING, "fork: parent tid=%d pid=%d -> child tid=%d pid=%d\n",   
                        nlcn_msg.proc_ev.event_data.fork.parent_pid,            
                        nlcn_msg.proc_ev.event_data.fork.parent_tgid,           
                        nlcn_msg.proc_ev.event_data.fork.child_pid,             
                        nlcn_msg.proc_ev.event_data.fork.child_tgid);           
                break;
            case PROC_EVENT_EXEC:                                               
                syslog(LOG_WARNING, "exec: tid=%d pid=%d name=%s\n",                         
                        nlcn_msg.proc_ev.event_data.exec.process_pid,           
                        nlcn_msg.proc_ev.event_data.exec.process_tgid,          
                        get_process_name_by_pid(nlcn_msg.proc_ev.event_data.exec.process_pid));
                break;                                                          
            case PROC_EVENT_UID:                                                
                syslog(LOG_WARNING, "uid change: tid=%d pid=%d from %d to %d\n",             
                        nlcn_msg.proc_ev.event_data.id.process_pid,             
                        nlcn_msg.proc_ev.event_data.id.process_tgid,            
                        nlcn_msg.proc_ev.event_data.id.r.ruid,                  
                        nlcn_msg.proc_ev.event_data.id.e.euid);                 
                break;                                                          
            case PROC_EVENT_GID:                                                
                syslog(LOG_WARNING, "gid change: tid=%d pid=%d from %d to %d\n",             
                        nlcn_msg.proc_ev.event_data.id.process_pid,             
                        nlcn_msg.proc_ev.event_data.id.process_tgid,            
                        nlcn_msg.proc_ev.event_data.id.r.rgid,                  
                        nlcn_msg.proc_ev.event_data.id.e.egid);                 
                break;
            case PROC_EVENT_EXIT:
                syslog(LOG_WARNING, "exit: tid=%d pid=%d exit_code=%d\n",
                        nlcn_msg.proc_ev.event_data.exit.process_pid,
                        nlcn_msg.proc_ev.event_data.exit.process_tgid,
                        nlcn_msg.proc_ev.event_data.exit.exit_code);
                break;
            default:
                syslog(LOG_WARNING, "unhandled proc event\n");
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

void litros_init(void) {

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
    
}

int parse_params(const char *args, struct rt_node_t *params)
{
    cJSON *root = NULL;
    static int tmp_int;
    static char tmp_str[64];
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

    strcpy(tmp_str, cJSON_GetObjectItem(root, "res_str")->valuestring);
    params->res_str = tmp_str;
    strcpy(tmp_str, cJSON_GetObjectItem(root, "task_id")->valuestring);
    params->task_id = tmp_str;
    
    params->res_type = parse_reservation_type(params->res_str);
    return 0;
}

#define OPTSTR "d:"

int main(int argc, char **argv)
{
    pid_t pid;
    pthread_t io_tid;

    int nl_sock;
    int ret = EXIT_SUCCESS;
    int opt;
    struct litros_global_t *global;
     
    char config_str[MAX_CONFIG_LEN] = "";
    char config_filename[128] = "";
    FILE *config_fp = NULL;
    size_t config_len;

    char directory[128] = "";
    DIR *dp = NULL;
    struct dirent *ep = NULL;
    size_t dir_len;
    struct rt_node_status_t *tmp_status;

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
    litros_init();

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
    CALL ( pthread_mutex_init(global->mutex, NULL) );
    LIST_INIT(&global->head); 

    while ( (ep = readdir(dp)) ) {
        sprintf(config_filename, "%s%s", directory, ep->d_name);
        if (ep->d_type != DT_REG)
            continue;
        syslog(LOG_WARNING, "reading configuration from %s", config_filename);
        config_fp = fopen(config_filename, "r");
        config_len = fread(config_str, sizeof(char), MAX_CONFIG_LEN, config_fp);
        if (config_len == 0) {
            syslog(LOG_WARNING, "empty file %s", ep->d_name);
        }
        else{
            config_str[++config_len] = '\0';
            tmp_status = malloc(sizeof(struct rt_node_status_t));
            tmp_status->node = malloc(sizeof(struct rt_node_t));
            tmp_status->is_rt = 0; 
            ret = parse_params(config_str, tmp_status->node);
            if (ret != 0)
                syslog(LOG_ERR, "could not parse JSON file %s", ep->d_name);
            else {
                syslog(LOG_WARNING, "parsed JSON file %s", ep->d_name);
                syslog(LOG_WARNING, "node parameters:\n%s", 
                        param_to_str(tmp_status->node));
                LIST_INSERT_HEAD(&global->head, tmp_status, list);
            }
        }
    }
    if (errno == EBADF)
        syslog(LOG_ERR, "readdir(): %s", strerror(errno));

    pthread_create(&io_tid, NULL, check_file_changes, global);

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
    
    pthread_cancel(io_tid);
    set_proc_ev_listen(nl_sock, false);
    free(global);

out:
    close(nl_sock);
    return ret;
}
