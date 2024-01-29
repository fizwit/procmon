/*
 *  proc_mon.c
 *
 *  2016.01.16  John Dey
 *
 *  Log user level commands with command line arguments. Log messages
 *  are written in JSON format to /var/log/proc_mon.log. Listen to all
 *  kernel process events with proc connector.  proc_mon receives notification
 *  of all process events from the kernel.
 *
 *  Process events are delivered through a socket-based
 *  interface by reading instances of struct proc_event defined in the
 *  kernel header. Netlink is used to transfer information between kernel
 *  modules and user space processes.
 *
 *  Filter process events for EXEC and only log processes messages from
 *  non-root users.
 *
 *  Most of the code is liberally copied from Matt Helsley's proc
 *  connector test code.
 *
 *  improve by filtering at Kernel level before messages are sent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
// include <linux/a.out.h> outdated on newer kernels

#define VERSION "1.1.0"   /* change field name host to node */
int  DEBUG = 0;  /* FLAG set if cmd line arg is specifified */

static char* PID_FILE = "/var/run/proc_mon.pid";
char Hostname[1024];
void get_cmdline(pid_t pid);
int  fd_pid;

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int
nl_connect()
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
 * turn on/off the proc events (process notifications)
 * enable bool:  Listen/Ignore
 *
 */
static int
set_proc_ev_listen(int nl_sock, bool enable)
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

/*
 * handle a single process event
 */
static volatile bool need_exit = false;
static int
handle_proc_ev(int nl_sock)
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
            if (errno == EINTR)
                continue;
            perror("netlink recv");
            return -1;
        }
        if (nlcn_msg.proc_ev.what == PROC_EVENT_EXEC) {
            get_cmdline( nlcn_msg.proc_ev.event_data.exec.process_tgid);
        }
    }
    return 0;
}

#include <time.h>
#include <sys/time.h>
char*
ISO8601_timestamp()
{
    static char ts[32];
    time_t uct_sec;
    struct tm *uct_tm;

    uct_sec = time(NULL);
    uct_tm = gmtime(&uct_sec);
    snprintf(ts, sizeof(ts), "%d.%02d.%02dT%02d:%02d:%02dZ",
       uct_tm->tm_year+1900,
       uct_tm->tm_mon + 1,
       uct_tm->tm_mday,
       uct_tm->tm_hour,
       uct_tm->tm_min,
       uct_tm->tm_sec );
   return ts;
}

#define CMDSZ 4096    /* length of /proc/pid/cmdline */
#define BUFSZ 8192    /* twice size of PAGESIZE */
#define BIGBUF 8192+128  /* cmdline + meta data */
#define SMBUF 1024

#define TargetLen 3
static char *targets[TargetLen] = {"Name:", "PPid:", "Uid:"}; /* select items from /proc/pid/status */
static char *outputs[TargetLen] = {"name",  "ppid",  "uid"};  /* output formated */

/*
 * pid  = process ID
 *
 * given a PID get the command line and UID
 * of a process
 *
 * Note: /proc/pid/cmdline is 4096 in size.  defined as PAGE_SIZE in Linux
 *
 * Perform minimal cleanup of 'cmdline' for JSON output;
 *   escape double quote " becomes \"
 *   escape escape char \ becomes \\
 *   and remove control charaters.
 *
 * This routine is longer an unglier that it should be. All work is performed
 * within this one routine during an interupt.
 */
#define FLEN 32
void
get_cmdline(pid_t pid)
{
    char fname_cmd[FLEN], fname_status[FLEN], buf[CMDSZ+1], cmdline[BUFSZ+1];
    char status_buf[SMBUF+1];
    char outbuf[BIGBUF];
    char json[SMBUF+1];
    char *ptr, *s, *t, *p;
    int i, j, count, slen, status_len, fd, fd_status;
    int len, cnt =0;

    snprintf(fname_cmd, FLEN, "/proc/%ld/cmdline", (long)pid);
    snprintf(fname_status, FLEN, "/proc/%ld/status", (long)pid);
    if ( (fd = open(fname_cmd, O_RDONLY)) == -1) {
       syslog(LOG_NOTICE, "process missed: %ld", (long)pid);
       return;
    }
    if ( (fd_status = open(fname_status, O_RDONLY)) == -1) {
       syslog(LOG_NOTICE, "could not open: %s", fname_status);
    }
    if ( (status_len = (int)read(fd_status, status_buf, SMBUF)) == -1) {
       syslog(LOG_NOTICE, "could not read: %s", fname_cmd);
       return;
    }
    /*
     *  parse /proc/pid/status convert to JSON
     */
    s = json;
    ptr = status_buf;
    for(i=0; i<status_len; i++)
       if (status_buf[i] == '\n')
           status_buf[i] = '\0';
    while ( cnt < TargetLen) {
        for (i=0; i<TargetLen; i++) {
            len = strlen(targets[i]);
            if (strncmp(ptr, targets[i], len) == 0) {
                p = ptr + len + 1;
                while (isspace(*p)) ++p;
                t = p;
                while(*t && !isspace(*t)) ++t;
                *t = '\0';
                if ( i == 2 && *p == '0') {  /* UID=0 Ignore root processes */
                   close(fd);
                   close(fd_status);
                   return;
                }
                if (cnt) { strcat(s, ", "); s += 2; }
                snprintf(s, SMBUF, "\"%s\": \"%s\"", outputs[i], p);
                while (*s) s++;
                cnt++;
             }
        }
        while(*ptr) ++ptr; ++ptr; /* advance to end of string */
    }
    close(fd_status);
    /*
     * fix cmdline
     */
    if ( (slen = (int)read(fd, buf, CMDSZ)) == -1) {
       syslog(LOG_NOTICE, "could not read: %s", fname_cmd);
       return;
    }
    for(i=0,j=0; i<slen; i++) /* convert cmdline to single string and make JSON safe */
       if (buf[i] == '\0')
          cmdline[j++] = ' ';
       else if (buf[i] < 32 || buf[i] > 126 ) /* remove control char */
          continue;
       else if ( buf[i] == '"' || buf[i] == '\\') {
          cmdline[j++] = '\\';
          cmdline[j++] = buf[i];
       }
       else
          cmdline[j++] = buf[i];
    cmdline[j] = '\0';
    close(fd);
    count = snprintf(outbuf, BIGBUF, "{\"timestamp\": \"%s\", \"node\": \"%s\", \"pid\": %ld, %s, \"cmdline\": \"%s\"}",
            ISO8601_timestamp(), Hostname, (long)pid, json, cmdline);
    if (count < 0 || count > BIGBUF)
           syslog(LOG_NOTICE, "error output buffer truncated: %s", outbuf);
    syslog(LOG_INFO, "%s", outbuf);
}

/*
 * TERM and INT both cuase us to terminate
 */
static void
on_sigint(int unused)
{
    syslog(LOG_NOTICE, "terminated");
    void closelog();
    unlink(PID_FILE);
    need_exit = true;
}

void
print_help(const char* name)
{
    printf("%s: Monitor kernel Proc Connector.\n", name);
    fputs(" write non-root Exec calls to /var/log/proc_mon.log\n", stdout);
    fputs(" --help print this message\n", stdout);
    fputs(" --debug write messages to to standard out stay if forground\n", stdout);
    fputs(" --daemon detach process and write messages to logfile\n", stdout);
    fputs("  debug and daemon modes are exclusive\n", stdout);
    exit(EXIT_SUCCESS);
}
/*
 * daemonize -- only for non systemd Linux
 * Save to remove this code with systemd (and update main)
 */

static void
daemon_init()
{
    pid_t pid;

    /* Change the working directory to the root directory */
    if (chdir("/")) {
        perror("could not chdir to /");
        exit(EXIT_FAILURE);
    }

    /* Fork off the parent process */
    if ((pid = fork()) < 0)
        exit(EXIT_FAILURE); /* error */
    else if (pid != 0)
        exit(EXIT_SUCCESS); /* Success: terminate the parent */

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Fork off for the second time*/
    if ((pid = fork()) < 0)
        exit(EXIT_FAILURE);    /* An error occurred */
    else if (pid != 0)
        exit(EXIT_SUCCESS);  /* Success: Let the parent terminate */

    /* Set new file permissions */
    umask(0);

    /* Close all open file descriptors */
    int x;
    for (x = 0; x<3; x++)
        close (x);

    /* Open the log file */
    openlog (NULL, 0, LOG_USER);   /* old: openlog("proc_mon", LOG_PID, LOG_DAEMON); */
}

int
write_pid()
{
    char buf[32];
    int pid_file = open(PID_FILE, O_CREAT | O_RDWR, 0644);
    int rc = flock(pid_file, LOCK_EX | LOCK_NB);

    if (rc) {
        if (EWOULDBLOCK == errno) {
            syslog(LOG_NOTICE, "pid exists exiting");
        } else {
            syslog(LOG_NOTICE, "issue with pid file");
        }
        exit(EXIT_FAILURE);
    } else {
        snprintf(buf, 32, "%ld", (long)getpid() );
        if ( write(pid_file, buf, strlen(buf)) != strlen(buf)) {
            syslog(LOG_NOTICE, "write to pid file failed");
            exit(EXIT_FAILURE);
        }
    }
    return pid_file;
}

/*
 * debug and daemon flags are exclusive; can't be both
 */
void
process_args(int argc, const char *argv[])
{
    int i;

    for(i=1; i<argc; i++)
        if ( !strcmp(argv[i], "--version") ) {
           printf("%s  version: %s\n", argv[0], VERSION);
           exit(EXIT_SUCCESS);
        }
        else
        if ( !strcmp(argv[i], "--help") )
           print_help(argv[0]);
        else
        if ( !strcmp(argv[i], "--debug") )
           DEBUG == 1;
        else
        if  ( !strcmp(argv[i], "--daemon") ) {
           daemon_init();
           fd_pid = write_pid();
        }
}

int
main(int argc, const char *argv[])
{
    int nl_sock;
    int rc = EXIT_SUCCESS;

    process_args(argc, argv);

    /* Catch, ignore and handle signals */
    // This is outdated
    // signal(SIGINT, &on_sigint);
    // signal(SIGHUP, &on_sigint);
    // siginterrupt(SIGINT, true);
    //
    struct sigaction sa;
    sa.sa_handler = &on_sigint;
    sa.sa_flags = SA_RESTART; // Automatically restart certain system calls
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Error: cannot handle SIGINT"); // Should not happen
    }

    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        perror("Error: cannot handle SIGHUP"); // Should not happen
    }

    gethostname(Hostname, 1024);

    nl_sock = nl_connect();
    if (nl_sock == -1)
        exit(EXIT_FAILURE);

    syslog(LOG_NOTICE, "started");
    rc = set_proc_ev_listen(nl_sock, true);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }

    rc = handle_proc_ev(nl_sock);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }

    set_proc_ev_listen(nl_sock, false);

out:
    close(nl_sock);
    exit(rc);
}

