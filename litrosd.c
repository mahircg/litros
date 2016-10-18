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

#include "cJSON.h"
#include "litros_rt_param.h"

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


const char *usage_msg = 
    "Usage: litrosd OPTIONS\n"
    "Options:\n"
    "\t-d:\tFolder where node configuration files and metadata are stored";

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

static const char *directory = NULL;

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
        sprintf(name, "/proc/%d/cmdline",pid);                                  
        f = fopen(name,"r");                                              
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

static volatile bool need_exit = false;

struct litros_global_t {
    pthread_mutex_t *mutex;
}

struct litros_thread_local_t {
        struct litrosd_global *global;
        int event_id;
};

void *thread_cleanup(void *args) {
    struct litros_thread_local_t *local = (struct litros_thread_local_t*)args;
    
    pthread_mutex_unlock(local->global->mutex);
    close(local->event_id);
}

void *check_file_changes(void *args) 
{
    int event_id;
    struct litros_global_t *global;
    struct litros_thread_local_t local;


    memset(&local, 0, sizeof(litro_thread_local_t));
    global = (struct litrosd_global*)args;

    event_id = inotify_init();
    if (event_id < 0) {
        syslog(LOG_WARNING, "inotify_init() failed. litrosd will not detect"
        "changes in configuration file directory");
        return;
    }

    local.global = global;
    local.event_id = event_id;
    
    pthread_cleanup_push(thread_cleanup, &local);
    
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

#define OPTSTR "d:"
int main(int argc, char **argv) {
    pid_t pid;
    int nl_sock;
    int ret = EXIT_SUCCESS;
    int opt;
    struct litrosd_global global;
    pthread_t io_tid;

    while ((opt = getopt(argc, argv, OPTSTR)) != -1) {
        switch (opt) {
            case 'd':
                directory = optarg;
                break;
            default:
                usage("bad argument");
                break;            
        }
    }

    if (directory == NULL) {
        usage("directory must be specified with -d");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    else if (pid > 0)
        exit(EXIT_SUCCESS);

    litros_init();

    memset(&global, 0, sizeof(struct litrosd_global));
    CALL (pthread_mutex_init(global->mutex, NULL) );

    pthread_crate(&io_tid, NULL, check_file_changes, &global);

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

    set_proc_ev_listen(nl_sock, false);

out:
    close(nl_sock);
    return ret;
}
