/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2013, MindBricks Technologies               *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
*                     MindBricks Confidential Proprietary.                     *
*                            All Rights Reserved.                              *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <sys/mman.h>

#include <syslog.h> /** logging */

#include <errno.h>

#include <stun_base.h>
#include <stun_enc_dec_api.h>
#include <turns_api.h>
#include <stuns_api.h>
#include <ice_server.h>


/** need to move the realm into configuration */
#define ICE_SERVER_REALM    "mindbricks.com"

#if 0
char *log_levels[] =
{    
    "LOG_SEV_EMERG",
    "LOG_SEV_ALERT",
    "LOG_SEV_CRITICAL",
    "LOG_SEV_ERROR",
    "LOG_SEV_WARNING",
    "LOG_SEV_NOTICE",
    "LOG_SEV_INFO",
    "LOG_SEV_DEBUG",
};
#endif

static void iceserver_sig_handler(int signum);


typedef struct 
{
    int signum;
    void (*handler)(int signum);
} iceserver_signal_t;

#define MQ_WORKER_DB    "/mb_ice_mq_worker_db"
#define MQ_DB_WORKER    "/mb_ice_mq_db_worker"

static iceserver_signal_t signals_list[] =
{
    { SIGHUP, iceserver_sig_handler },
    { SIGINT, iceserver_sig_handler },
    { SIGQUIT, iceserver_sig_handler },
    { SIGILL, iceserver_sig_handler },
    { SIGABRT, iceserver_sig_handler },
    { SIGBUS, iceserver_sig_handler },
    //{ SIGSEGV, iceserver_sig_handler },
    { SIGCHLD, iceserver_sig_handler },
}; 


/** the global instance of server */ 
mb_ice_server_t g_mb_server = {0};
mb_iceserver_worker_list_t *gaps_workers;
stun_log_level_t g_loglevel = LOG_SEV_DEBUG;
int iceserver_quit = 0;

void *mb_iceserver_decision_thread(void);


static void iceserver_sig_handler(int signum)
{
    static pid_t pid, ppid;
    pid = getpid();
    ppid = getppid();
    iceserver_quit = 1;
    printf("Quiting - Signal : %d PID: %d PPID: %d\n", signum, pid, ppid);
    ICE_LOG(LOG_SEV_ALERT,
            "Quiting - Signal : %d PID: %d PPID: %d\n", signum, pid, ppid);
    return;
}



void app_log(stun_log_level_t level,
        char *file_name, uint32_t line_num, char *format, ...)
{
    char buff[500];
    va_list args;
    int relative_time;
    static struct timeval init = { 0, 0 };
    struct timeval now;

    if (level > g_loglevel) return;

    if(init.tv_sec == 0 && init.tv_usec == 0)
        gettimeofday(&init, NULL);

    gettimeofday(&now, NULL);

    relative_time = 1000 * (now.tv_sec - init.tv_sec);
    if (now.tv_usec - init.tv_usec > 0)
        relative_time = relative_time + ((now.tv_usec - init.tv_usec) / 1000);
    else
        relative_time = relative_time - 1 + ((now.tv_usec - init.tv_usec) / 1000);

    va_start(args, format);

#if 0
    sprintf(buff, "| %s | %i msec <%s: %i> %s\n", 
            log_levels[level], relative_time, file_name, line_num, format);
    vprintf(buff, args );
#else
    sprintf(buff, "<%s: %i> %s", file_name, line_num, format);
    vsyslog(level, buff, args);
#endif

    va_end(args );
}


static void ice_server_timer_expiry_cb (void *timer_id, void *arg)
{
    ssize_t bytes = 0;
    mb_ice_server_timer_event_t timer_event;

    ICE_LOG(LOG_SEV_DEBUG, "[MB ICE SERVER] in sample application timer "\
            "callback %d %p", (int)timer_id, arg);

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;

    bytes = send(g_mb_server.timer_sockpair[1], 
            (u_char *)&timer_event, sizeof(timer_event), 0);
    if (bytes == -1)
        ICE_LOG(LOG_SEV_ERROR, "Error: Sending of timer event failed");
    
    return;
}



static int32_t ice_server_network_send_data(u_char *data, 
        uint32_t data_len, stun_inet_addr_type_t ip_addr_type, 
        u_char *ip_addr, uint32_t port, handle transport_param, u_char *key)
{
    int32_t sent_bytes = 0;
    int ret, sock_fd = (int) transport_param;
    struct sockaddr dest;

    if (ip_addr_type == STUN_INET_ADDR_IPV4)
    {
        dest.sa_family = AF_INET;
        ((struct sockaddr_in *)&dest)->sin_port = htons(port);
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in *)&dest)->sin_addr));
        if (ret != 1)
        {
            ICE_LOG(LOG_SEV_WARNING, "inet_pton failed\n");
            return sent_bytes;
        }
    }
    else if (ip_addr_type == STUN_INET_ADDR_IPV6)
    {
        dest.sa_family = AF_INET6;
        ((struct sockaddr_in6 *)&dest)->sin6_port = htons(port);
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in6 *)&dest)->sin6_addr));
        if (ret != 1) return sent_bytes;
    }
    else
    {
        app_log (LOG_SEV_INFO, __FILE__, __LINE__,
                "[ICE AGENT DEMO] Invalid IP address family type. "\
                "Sending of STUN message failed");
        return sent_bytes;
    }

    sent_bytes = sendto(sock_fd, data, data_len, 0, &dest, sizeof(dest));
    if (sent_bytes == -1)
    {
        printf("ERROR: Worker %d Sending of relay data on socket fd %d failed\n", getpid(), sock_fd);
        perror("sendto");
    }

    printf("Worker %d: Sent TURN DATA message of %d bytes\n", getpid(), sent_bytes);

    return sent_bytes;
}



static int32_t ice_server_network_send_msg(handle h_msg, 
        stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
        uint32_t port, handle transport_param, u_char *key)
{
    int32_t status, sent_bytes = 0;
    int ret, sock_fd = (int) transport_param;
    static char buf[1500];
    uint32_t buf_len = 1500;
    struct sockaddr dest;
    stun_auth_params_t auth;

    stun_memset(&auth, 0, sizeof(auth));

    if (key)
    {
        /** 
         * long term auth key length is always 16 
         * since it is always md5 derived.
         */
        auth.key_len = 16;
        stun_memcpy(&auth.key, key, auth.key_len);
    }

    /** encode the message */
    status = stun_msg_encode(h_msg, &auth, (uint8_t *)buf, &buf_len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_WARNING, "Sending of STUN message failed");
        return STUN_TRANSPORT_FAIL;
    }

    if (ip_addr_type == STUN_INET_ADDR_IPV4)
    {
        dest.sa_family = AF_INET;
        ((struct sockaddr_in *)&dest)->sin_port = htons(port);
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in *)&dest)->sin_addr));
        if (ret != 1)
        {
            ICE_LOG(LOG_SEV_ERROR, "inet_pton failed");
            return sent_bytes;
        }
    }
    else if (ip_addr_type == STUN_INET_ADDR_IPV6)
    {
        dest.sa_family = AF_INET6;
        ((struct sockaddr_in6 *)&dest)->sin6_port = htons(port);
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in6 *)&dest)->sin6_addr));
        if (ret != 1) return sent_bytes;
    }
    else
    {
        app_log (LOG_SEV_INFO, __FILE__, __LINE__,
                "[ICE AGENT DEMO] Invalid IP address family type. "\
                "Sending of STUN message failed");
        return sent_bytes;
    }

    sent_bytes = sendto(sock_fd, buf, buf_len, 0, &dest, sizeof(dest));
    if (sent_bytes == -1)
    {
        printf("ERROR: Worker %d Sending of TURN message on socker fd %d failed\n", getpid(), sock_fd);
        perror("sendto");
    }

    printf("Worker %d: Sent TURN message of %d bytes\n", getpid(), sent_bytes);

    return sent_bytes;
}



int32_t ice_server_share_with_other_workers(int sock_fd, int op_type)
{
    struct msghdr msgh;
    struct iovec iov[1];
    struct cmsghdr *cmsgp = NULL;
    char buf[CMSG_SPACE(sizeof(sock_fd))];
    int bytes, i;
    pid_t pid;
    mb_iceserver_worker_t *worker;
    mb_ice_server_aux_data_t aux_data;

    /** TODO - are these really necessary? performance? */
    memset(&msgh, 0, sizeof(msgh));
    memset(buf, 0, sizeof(buf));

    aux_data.sock_fd = sock_fd;
    aux_data.op_type = op_type;

    /** because we are making use of stream/connected sockets */
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;

    iov[0].iov_base = (char *) &aux_data;
    iov[0].iov_len = sizeof(aux_data);

    msgh.msg_control = buf;
    msgh.msg_controllen = sizeof(buf);

    cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(sock_fd));

    /** copy the socket descriptor value */
    *((int *)CMSG_DATA(cmsgp)) = sock_fd;
    msgh.msg_controllen = cmsgp->cmsg_len;

    pid = getpid();

    for (i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
    {
        worker = &gaps_workers->workers[i];

        if (worker->pid == pid) continue;

        do
        {
            bytes = sendmsg(worker->sockpair[1], &msgh, 0);
        } while((bytes == -1) && (errno == EINTR));
    }

    return STUN_OK;
}



static int32_t ice_server_create_socket(handle h_alloc, 
        stun_inet_addr_type_t addr_family, char *ip_addr, 
        stun_transport_protocol_type_t tport_proto, int *port, int *sock_fd)
{
    int i, sock, sock_type, ret;
    struct sockaddr addr;
    unsigned short sa_family;
    int32_t status;

    /**
     * how do we decide whether the client is requesting an IPv6
     * or an IPv4 relayed address? Currently using the local interface
     * address on which the request was received, to decide the same.
     */
    if (addr_family == STUN_INET_ADDR_IPV4)
        sa_family = AF_INET;
    else if (addr_family == STUN_INET_ADDR_IPV6)
        sa_family = AF_INET6;
    else
        return STUN_INT_ERROR;

    if (sa_family == AF_INET)
    {
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in *)&addr)->sin_addr));
        if (ret != 1) return STUN_INT_ERROR;
    }
    else
    {
        ret = inet_pton(AF_INET, (char *)ip_addr, 
                    &(((struct sockaddr_in6 *)&addr)->sin6_addr));
        if (ret != 1) return STUN_INT_ERROR;
    }

    if (tport_proto == ICE_TRANSPORT_UDP)
        sock_type = SOCK_DGRAM;
    else if (tport_proto == ICE_TRANSPORT_TCP)
        sock_type = SOCK_STREAM;
    else
        return STUN_INT_ERROR;


    sock = socket(sa_family, sock_type, 0);
    if (sock == -1) return STUN_NO_RESOURCE;

    /** 
     * set the socket to non-blocking. This is because on linux, strange 
     * behavior is observed where select says that "data is available", but
     * subsequent recvfrom() blocks. This is mentioned in man page as well.
     */
    fcntl(sock, F_SETFL, O_NONBLOCK);

    addr.sa_family = sa_family;

    for (i = TURNS_PORT_RANGE_MIN; i <= TURNS_PORT_RANGE_MAX; i++)
    {
        if (sa_family == AF_INET)
            ((struct sockaddr_in *)&addr)->sin_port = htons(i);
        else
            ((struct sockaddr_in6 *)&addr)->sin6_port = htons(i);

        /** TODO - do we need to abstract the 'bind' to make it portable? */
        ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
        if (ret == -1)
        {
            ICE_LOG(LOG_SEV_DEBUG, "binding to port [%d] failed... "\
                   "perhaps port already being used? continuing the search", i);
            continue;
        }

        break;
    }

    if (i == TURNS_PORT_RANGE_MAX)
    {
        close(sock);
        return STUN_NO_RESOURCE;
    }

    *port = i;

    /** add it to the relay socket list */
    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i] == 0)
        {
            g_mb_server.relay_sockets[i] = sock;
            break;
        }

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
        ICE_LOG(LOG_SEV_ERROR, "Ran out of available "\
                "relay sockets. Hence not adding to the list");
        *port = 0;
        return STUN_NO_RESOURCE;
    }

    FD_SET(sock, &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < sock) g_mb_server.max_fd = sock;

    /** need to wake up the waiting pselect */
    ICE_LOG(LOG_SEV_INFO, 
            "Added a new relay socket: %d at index %d", sock, i);

    /** send ancillary data to other worker processes */
    status = ice_server_share_with_other_workers(sock, 1);
    /** TODO - need to check return value */

    *sock_fd = sock;

    ICE_LOG(LOG_SEV_ERROR, "Bound to a new relay socket fd %d", sock);

    return status;
}



static int32_t ice_server_add_socket(handle h_alloc, int sock_fd) 
{
    int32_t i, status;
    ICE_LOG(LOG_SEV_DEBUG, 
            "Now need to listen on this socket as well: %d", sock_fd);

    printf("worker %d: TURNS wants app to listen on socket %d\n", getpid(), sock_fd);

    /** add it to the list */
    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i] == 0)
        {
            g_mb_server.relay_sockets[i] = sock_fd;
            break;
        }

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
        ICE_LOG(LOG_SEV_ERROR, "Ran out of available "\
                "relay sockets. Hence not adding to the list");
        return STUN_NO_RESOURCE;
    }

    FD_SET(sock_fd, &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < sock_fd) g_mb_server.max_fd = sock_fd;

    /** need to wake up the waiting pselect */
    ICE_LOG(LOG_SEV_INFO, 
            "Added a new relay socket: %d at index %d", sock_fd, i);

    /** send ancillary data to other worker processes */
    status = ice_server_share_with_other_workers(sock_fd, 1);
    /** TODO - need to check return value */

    return status;
}



int32_t ice_server_get_max_fd(void)
{
    uint32_t i, max_fd = 0;
    mb_iceserver_worker_t *worker;
    int mypid = getpid();

    /** TODO - 
     * this should be optimized, recalculating the max_fd by traversing all 
     * sockets every time a relay socket is removed is expensive.
     */

    /** first interface sockets */
    for(i = 0; i < 2; i++)
    {
        if (g_mb_server.intf[i].sockfd > max_fd)
            max_fd = g_mb_server.intf[i].sockfd;
    }

    /** next DB message queue */
    if (g_mb_server.qid_db_worker > max_fd)
        max_fd = g_mb_server.qid_db_worker;

    /** timer interface */
    if (g_mb_server.timer_sockpair[0] > max_fd)
        max_fd = g_mb_server.timer_sockpair[0];

    /** socketpair with the master process */
    for (i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
    {
        worker = &gaps_workers->workers[i];
        if (worker->pid != mypid) continue;

        if (worker->sockpair[0] > max_fd) max_fd = worker->sockpair[0];
        break;
    }

    /** and at last, relay sockets */
    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i] > max_fd)
            max_fd = g_mb_server.relay_sockets[i];

    return max_fd;
}



static int32_t ice_server_remove_socket(handle h_alloc, int sock_fd) 
{
    int32_t i, status;
    ICE_LOG(LOG_SEV_ERROR, 
            "Now need to remove this socket from select: %d", sock_fd);

    /** remove it from the list */
    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i] == sock_fd)
        {
            g_mb_server.relay_sockets[i] = 0;
            break;
        }

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Trying to remove socket fd: %d from the relay sock queue. "\
            "But could not locate it within the relay sock list", sock_fd);
        return STUN_NOT_FOUND;
    }

    FD_CLR(sock_fd, &g_mb_server.master_rfds);

    /** re-calculate the max fd, painful job */
    if (g_mb_server.max_fd == sock_fd)
        g_mb_server.max_fd = ice_server_get_max_fd();

    /** close the relay socket */
    close(sock_fd);
    
    /** send ancillary data to other worker processes */
    status = ice_server_share_with_other_workers(sock_fd, 0);
    /** TODO - need to check return value */

    return STUN_OK;
}



static handle ice_server_start_timer (uint32_t duration, handle arg)
{
    handle timer_id = NULL;

    timer_expiry_callback timer_cb = ice_server_timer_expiry_cb;

    ICE_LOG(LOG_SEV_DEBUG, "ice_server: starting timer for duration %d "\
            "Argument is %p", duration, arg);

    timer_id = platform_start_timer(duration, timer_cb, arg);

    ICE_LOG(LOG_SEV_DEBUG, "timer id returned is %p", timer_id);

    return timer_id;
}



static int32_t ice_server_stop_timer (handle timer_id)
{
    ICE_LOG(LOG_SEV_DEBUG, "ice_server: stopping timer %p", timer_id);

    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


static int mb_worker_get_parent_sock(void)
{
    int i, mypid = getpid();

    for (i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
        if (gaps_workers->workers[i].pid == mypid)
            return gaps_workers->workers[i].sockpair[0];

    ICE_LOG(LOG_SEV_ALERT, 
            "Unable to find the parent socket for pid: %d", mypid);
    return 0;
}


static int32_t ice_server_new_allocation_request(
                handle h_alloc, turns_new_allocation_params_t *alloc_req)
{
    int ret;
    mb_ice_server_event_t event;

    memset(&event, 0, sizeof(event));

    /** 
     * This is messy! passing data between processes - 
     * need to find an elegant solution 
     */
    event.msg_type = MB_ISEVENT_NEW_ALLOC_REQ;
    memcpy(event.username, alloc_req->username, alloc_req->username_len);
    memcpy(event.realm, alloc_req->realm, alloc_req->realm_len);
    event.lifetime = alloc_req->lifetime;
    event.protocol = alloc_req->protocol;
    event.h_alloc = alloc_req->blob;

    event.ingress_bytes = 0;
    event.egress_bytes = 0;
    
    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main socket listener thread. So post
     * this allocation request message to the slave thread that will
     * decide whether the allocation is to be approved or not.
     * TODO - make use of NON_BLOCK flag for the message queue
     */
    ret = mq_send(g_mb_server.qid_worker_db, (char *)&event, sizeof(event), 0);
    if (ret != 0)
    {
        /** TODO - handle this error! send error resp to turn client? */
        ICE_LOG (LOG_SEV_ERROR, 
                "Error posting to the DB process message queue");
        return STUN_INT_ERROR;
    }
    
    ICE_LOG (LOG_SEV_DEBUG, 
            "Posted the message to the DB process message queue");

    return STUN_OK;
}


static int32_t ice_server_handle_allocation_events(
            turns_event_t event, turns_alloc_event_params_t *params)
            //turns_event_t event, handle h_alloc, handle app_blob)
{
    int ret;
    mb_ice_server_event_t mb_event;

    ICE_LOG(LOG_SEV_DEBUG, 
            "Received allocation event for allocation %p: ", params->h_alloc);

    if (event == TURNS_EV_DEALLOCATED)
        ICE_LOG(LOG_SEV_DEBUG, "TURNS_EV_DEALLOCATED");
    else if (event == TURNS_EV_BANDWIDTH)
        ICE_LOG(LOG_SEV_DEBUG, "TURNS_EV_BANDWIDTH");
    else
        ICE_LOG(LOG_SEV_WARNING, "Some unknown event received");

    memset(&mb_event, 0, sizeof(mb_event));

    /** 
     * This is messy! passing data between processes - 
     * need to find an elegant solution 
     */
    mb_event.msg_type = MB_ISEVENT_DEALLOC_NOTF;
    mb_event.h_alloc = params->h_alloc;
    mb_event.app_blob = params->app_blob;

    mb_event.ingress_bytes = params->ingress_bytes;
    mb_event.egress_bytes = params->egress_bytes;
    
    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main socket listener thread. So post
     * this allocation request message to the slave thread that will
     * decide how to respond to the specific event.
     */
    ret = mq_send(g_mb_server.qid_worker_db, 
                    (char *)&mb_event, sizeof(mb_event), 0);
    if (ret != 0)
    {
        /** TODO - handle error! send error response to turn client? */
        ICE_LOG (LOG_SEV_ERROR, 
            "Error while posting the message to the DB process message queue");
        return STUN_INT_ERROR;
    }

    ICE_LOG (LOG_SEV_DEBUG, 
            "Posted the message to the DB process message queue");

    return STUN_OK;
}


static int32_t iceserver_init_turns(void)
{
    int32_t status;
    turns_osa_callbacks_t osa_cbs;
    turns_event_callbacks_t event_cbs;

    /** initialize the turns module */
    status = turns_create_instance(
            MB_ICE_MAX_ALLOCATIONS_COUNT, &(g_mb_server.h_turns_inst));
    if (status != STUN_OK) return status;

    status = turns_instance_set_server_software_name(
            g_mb_server.h_turns_inst, MB_ICE_SERVER, strlen(MB_ICE_SERVER));
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** set the realm */
    status = turns_instance_set_realm(g_mb_server.h_turns_inst, 
                            ICE_SERVER_REALM, strlen(ICE_SERVER_REALM));
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** set up os callbacks */
    osa_cbs.nwk_stun_cb = ice_server_network_send_msg;
    osa_cbs.nwk_data_cb = ice_server_network_send_data;
    osa_cbs.new_socket_cb = ice_server_create_socket;
    osa_cbs.remove_socket_cb = ice_server_remove_socket;
    osa_cbs.start_timer_cb = ice_server_start_timer;
    osa_cbs.stop_timer_cb = ice_server_stop_timer;
    
    status = turns_instance_set_osa_callbacks(
                        g_mb_server.h_turns_inst, &osa_cbs);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** set up event callbacks */
    event_cbs.new_alloc_cb = ice_server_new_allocation_request;
    event_cbs.alloc_event_cb = ice_server_handle_allocation_events;

    status = turns_instance_set_event_callbacks(
                        g_mb_server.h_turns_inst, &event_cbs);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    status = turns_instance_set_nonce_stale_timer_value(
                    g_mb_server.h_turns_inst, MB_ICE_SERVER_NONCE_EXPIRY);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    return status;

MB_ERROR_EXIT:
    status = turns_destroy_instance(g_mb_server.h_turns_inst);
    return status;
}



static int32_t iceserver_deinit_turns(void)
{
    int32_t status;

    /** de-initialize the turns module */
    status = turns_destroy_instance(g_mb_server.h_turns_inst);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Deinitialization of the "\
                "turns module failed. Returned error status: %d\n", status);
    }

    return status;
}



static int32_t iceserver_init_stuns(void)
{
    int32_t status;
    stuns_osa_callbacks_t osa_cbs;

    /** init the stuns module */
    status = stuns_create_instance(&(g_mb_server.h_stuns_inst));
    if (status != STUN_OK) return status;

    status = stuns_instance_set_server_software_name(
            g_mb_server.h_stuns_inst, MB_ICE_SERVER, strlen(MB_ICE_SERVER));
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** set up os callbacks */
    osa_cbs.nwk_cb = ice_server_network_send_msg;
    osa_cbs.start_timer_cb = ice_server_start_timer;
    osa_cbs.stop_timer_cb = ice_server_stop_timer;
    
    status = stuns_instance_set_osa_callbacks(
                        g_mb_server.h_stuns_inst, &osa_cbs);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    return status;

MB_ERROR_EXIT:
    status = stuns_destroy_instance(g_mb_server.h_stuns_inst);
    return status;
}


static int32_t iceserver_deinit_stuns(void)
{
    int32_t status;

    /** de-init the stuns module */
    status = stuns_destroy_instance(g_mb_server.h_stuns_inst);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Deinitialization of the "\
                "stuns module failed. Returned error status: %d\n", status);
    }

    return status;
}


static void iceserver_worker_parent_killed(int signum)
{
    iceserver_quit = 1;
    ICE_LOG(LOG_SEV_EMERG, "Parent process has terminated. Cleanup and exit");
    return;
}


static int32_t worker_setup_timer_com_intf(void)
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_mb_server.timer_sockpair) == -1)
    {
        perror ("process timer socketpair");
        ICE_LOG (LOG_SEV_ALERT, 
                "creating timer socketpair() returned error for worker");
        return STUN_INT_ERROR;
    }

    return STUN_OK;
}


static mb_iceserver_worker_t* worker_init(void)
{
    int32_t i, status;
    pid_t pid;
    struct sigaction sa;
    mb_iceserver_worker_t *worker = NULL;

    pid = getpid();

    status = worker_setup_timer_com_intf();
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Unable to setup timer communication interface");
        return NULL;
    }

    if (platform_init() != true)
    {
        ICE_LOG(LOG_SEV_ALERT, 
                "Worker Process: platform initialization failed");
        return NULL;
    }

    /** register to be notified about the death of parent process */
    prctl(PR_SET_PDEATHSIG, SIGHUP, 0, 0, 0);

    /** register for the above signal */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = iceserver_worker_parent_killed;
    if (sigaction(SIGHUP, &sa, 0) == -1)
    {
        ICE_LOG(LOG_SEV_ERROR, "Worker Process: Registering signal "\
                "handler failed for signal: SIGHUP");
        /** TODO - rollback changes above */
        return NULL;
    }

    /** TODO */
    /** should we add the local socketpair() connected socket to the fd list? */

#if 0
Note: This has already been done in the master process
    /** add the message queue to the master fd set */
    FD_SET(g_mb_server.qid_db_worker, &g_mb_server.master_rfds);
    if (g_mb_server.qid_db_worker > g_mb_server.max_fd)
        g_mb_server.max_fd = g_mb_server.qid_db_worker;
#endif

    /** add the timer socket to the listener fd set */
    FD_SET(g_mb_server.timer_sockpair[0], &g_mb_server.master_rfds);
    if (g_mb_server.timer_sockpair[0] > g_mb_server.max_fd)
        g_mb_server.max_fd = g_mb_server.timer_sockpair[0];

    /** listen on the ipc interface for comm with the parent/other process */
    for (i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
    {
        worker = &gaps_workers->workers[i];
        if (worker->pid != pid) continue;

        FD_SET(worker->sockpair[0], &g_mb_server.master_rfds);
        if (worker->sockpair[0] > g_mb_server.max_fd)
            g_mb_server.max_fd = worker->sockpair[0];

        break;
    }

    if (i == MB_ICE_SERVER_NUM_WORKER_PROCESSES)
    {
        ICE_LOG(LOG_SEV_ALERT, "Could not start "\
                "listening on the worker process IPC socket pair");
        return NULL;
    }

    return worker;
}


static void ice_server_run(void)
{
    mb_iceserver_worker_t *worker;
    ICE_LOG(LOG_SEV_DEBUG, "Run Lola run");

    // sleep(15);

    worker = worker_init();
    if (worker == NULL)
    {
        ICE_LOG(LOG_SEV_ALERT, "Worker process initialization failed");
        return;
    }

    while (!iceserver_quit)
    {
        iceserver_process_messages(worker);
    }

    return;
}


static int32_t iceserver_setup_db_worker_ipcs(void)
{
    g_mb_server.qid_db_worker = mq_open(
            MQ_DB_WORKER, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0660, NULL);
    if (g_mb_server.qid_db_worker == (mqd_t) -1)
    {
        perror ("mq_open");
        ICE_LOG(LOG_SEV_ALERT, "Creation of DB-to-worker message queue failed");
        return STUN_INT_ERROR;
    }

    g_mb_server.qid_worker_db = mq_open(
            MQ_WORKER_DB, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0660, NULL);
    if (g_mb_server.qid_worker_db == (mqd_t) -1)
    {
        perror ("mq_open");
        ICE_LOG(LOG_SEV_ALERT, "Creation of Worker-to-DB message queue failed");
        return STUN_INT_ERROR;
    }

    ICE_LOG(LOG_SEV_DEBUG,
            "Message queues created for communication between DB processes and "
            "the worker processes");
    return STUN_OK;
}


static int32_t iceserver_setup_master_worker_ipcs(void)
{
    int32_t count;

    /** for communication between the db process and the master process */
    if (socketpair(AF_UNIX, 
                SOCK_STREAM, 0, g_mb_server.db_lookup.sockpair) == -1)
    {
        perror ("process socketpair");
        ICE_LOG (LOG_SEV_ALERT, 
                "process socketpair() returned error for DB process");
        return STUN_INT_ERROR;
    }

    ICE_LOG(LOG_SEV_DEBUG, 
            "Create DB lookup process socket: %d to fd_set", 
            g_mb_server.db_lookup.sockpair[0]);

    /** communication between master and each of the worker processes */
    for (count = 0; count < MB_ICE_SERVER_NUM_WORKER_PROCESSES; count++)
    {
        if (socketpair(AF_UNIX, SOCK_STREAM, 
                    0, gaps_workers->workers[count].sockpair) == -1)
        {
            perror ("process socketpair");
            ICE_LOG (LOG_SEV_ALERT, "process socketpair() "\
                    "returned error for Worker process %d", count);
            return STUN_INT_ERROR;
        }
    }

    return STUN_OK;
}



static int32_t iceserver_prepare_listener_fdset(void)
{
    int32_t i;

    /** add stun packet listener sockets */
    for(i = 0; i < 2; i++)
    {
        if (g_mb_server.intf[i].sockfd)
            FD_SET(g_mb_server.intf[i].sockfd, &g_mb_server.master_rfds);
        if (g_mb_server.max_fd < g_mb_server.intf[i].sockfd)
            g_mb_server.max_fd = g_mb_server.intf[i].sockfd;
    }

#if 0
    /** NOTE: Following are required to be done by the master process */

    /** add ipc fds for db process */
    FD_SET(g_mb_server.db_lookup.sockpair[1], &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < g_mb_server.db_lookup.sockpair[1])
        g_mb_server.max_fd = g_mb_server.db_lookup.sockpair[1];


    /** add ipc fds for worker processes */
    for(i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
    {
        if (g_mb_server.workers[i].sockpair[1])
            FD_SET(g_mb_server.workers[i].sockpair[1], &g_mb_server.master_rfds);
        if (g_mb_server.max_fd < g_mb_server.workers[i].sockpair[1])
            g_mb_server.max_fd = g_mb_server.workers[i].sockpair[1];
    }
#endif

    /** add the DB to worker processes message queue */
    FD_SET(g_mb_server.qid_db_worker, &g_mb_server.master_rfds);
    if (g_mb_server.qid_db_worker > g_mb_server.max_fd)
        g_mb_server.max_fd = g_mb_server.qid_db_worker;

    return STUN_OK;
}


void iceserver_init_log(void)
{
    char *ident = "MindBricks";
    int logopt = LOG_PID | LOG_CONS | LOG_NDELAY;
    int facility = LOG_USER;

    openlog(ident, logopt, facility);
}



void iceserver_init_sig_handlers(void)
{
    int i;
    struct sigaction sa;
    iceserver_signal_t *handler;
    int num_signals = sizeof(signals_list)/sizeof(iceserver_signal_t);


    for (i = 0; i < num_signals; i++)
    {
        handler = &signals_list[i];
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler->handler;
        if (sigaction(handler->signum, &sa, 0) == -1)
        {
            ICE_LOG(LOG_SEV_ERROR, "Registering signal handler failed for "\
                    "signal: %d", handler->signum);
        }
    }

    return;
}


static int32_t iceserver_launch_workers(void)
{
    pid_t child_pid;
    int32_t count, i, status;

    child_pid = fork();
    if (child_pid == -1)
    {
        ICE_LOG(LOG_SEV_ALERT, "Forking of the database process failed");
        return STUN_INT_ERROR;
    }
    else if (child_pid == 0)
    {
        mb_iceserver_decision_thread();
    }
    else
    {
        g_mb_server.db_lookup.pid = child_pid;
        ICE_LOG(LOG_SEV_ALERT, "DB worker spawned. PID: %d", child_pid);
        printf("DB worker spawned. PID: %d\n", child_pid);
    }

    for (count = 0; count < MB_ICE_SERVER_NUM_WORKER_PROCESSES; count++)
    {
        child_pid = fork();

        if (child_pid == -1)
        {
            /** unable to create the worker process, bail out! */
            ICE_LOG(LOG_SEV_ALERT, 
                    "Unable to create the worker process using fork()");
            status = STUN_INT_ERROR;
            goto MB_ERROR_EXIT;
        }
        else if (child_pid == 0)
        {
            ice_server_run();
        }
        else
        {
            gaps_workers->workers[count].pid = child_pid;
            ICE_LOG(LOG_SEV_ALERT, "Worker spawned. PID: %d", child_pid);
            printf("Worker[%d] spawned. PID: %d\n", count, child_pid);
        }
    }

    return STUN_OK;

MB_ERROR_EXIT:

    for (i = 0; i < count; i++)
    {
        /** TODO - kill child process */
    }

    /** TODO - kill db process */

    return status;
}



mb_iceserver_worker_list_t* iceserver_init_shared_globals(void)
{
    uint32_t fd, i, size;
    char zero = 0;
    mb_iceserver_worker_list_t *data = NULL;

    /** remove shared memory object if it exists */
    shm_unlink(MB_ICE_SERVER_MMAP_FILE_PATH);

    /** open file for shared memory access */
    fd = shm_open(MB_ICE_SERVER_MMAP_FILE_PATH, O_RDWR | O_CREAT, S_IRWXU);
    if (fd == -1)
    {
        perror("ICE SERVER shared memory open");
        ICE_LOG(LOG_SEV_ALERT, 
                "ICE SERVER: opening the shared memory file failed");
        return data;
    }

    size = sizeof(mb_iceserver_worker_list_t);
    if (ftruncate(fd, size) < 0)
    {
        perror("ICE SERVER: shared memory ftruncate");
        ICE_LOG(LOG_SEV_ALERT, 
                "ICE SERVER: Truncating the shared mem file failed");
        close(fd);
        return data;
    }

    /** write some data TODO - need to optimize? */ 
    for (i = 0; i < size; i++) write(fd, &zero, sizeof(char));
    //write(fd, &zero, size);

    /**
     * TODO - the allocation size is desired to be in multiple of the PAGESIZE
     * since internally mmap deals only with pages, and it is desirable that
     * they are aligned to the page boundary. Typical page sizes - 4096/8192.
     */

    /** allocate shared memory */
    data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == (void *) -1)
    {
        perror("ICE SERVER shared mem mmap:");
        ICE_LOG(LOG_SEV_ALERT,
                "ICE SERVER: allocation of shared memory failed");
        return data;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "ICE SERVER Allocated shared memory of size: [%d] bytes", size);

    close(fd);

    return data;
}



int main (int argc, char *argv[])
{
    int32_t status, i;
    int options = 0;
    siginfo_t siginfo;

    printf ("MindBricks: SeamConnect ICE server booting up...\n");

    memset(&g_mb_server, 0, sizeof(mb_ice_server_t));

#if 1
    /** daemonize */
    if (daemon(0, 0) == -1)
    {
        printf("Could not be daemonized\n");
        exit(-1);
    }
    printf("Running as a daemon in the background\n");
#endif

    gaps_workers = iceserver_init_shared_globals();
    if (gaps_workers == NULL)
    {
        ICE_LOG(LOG_SEV_ALERT,
                "ICE SERVER: Initialization of the global data failed");
        exit(-1);
    }

    /** set up logging */
    iceserver_init_log();
    ICE_LOG(LOG_SEV_ALERT, "MindBricks: SeamConnect ICE server booting up...");

    /** setup the signal handlers */
    iceserver_init_sig_handlers();

    /** initialize the turns module */
    status = iceserver_init_turns();
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "TURNS module initialization failed");
        ICE_LOG(LOG_SEV_ALERT, "Bailing out!!!");
        exit(-1);
    }

    /** initialize the stuns module */
    iceserver_init_stuns();
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "STUNS module initialization failed");
        ICE_LOG(LOG_SEV_ALERT, "Bailing out!!!");
        exit(-1);
    }

    /** initialize the transport module */
    if (iceserver_init_transport() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Initialization of transport failed");
        return -1;
    }

    /** setup IPC between the child processes and the master process */
    if (iceserver_setup_master_worker_ipcs() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Initialization of "\
                "IPC between master and worker processes failed");
        return -1;
    }

    /** setup IPC between worker processes and the db processes */
    if (iceserver_setup_db_worker_ipcs() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Initialization of "\
                "IPC between db process and worker processes failed");
        return -1;
    }

    /** prepare the socket listener set used by signaling worker processes */
    if (iceserver_prepare_listener_fdset() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Preparation of socket listener fdset failed");
        return -1;
    }

    printf("Master process. PID: %d\n", getpid());

    /** spin off the db and worker processes */
    if (iceserver_launch_workers() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, "Launching of worker processes failed");
        return -1;
    }

    /** 
     * TODO - now wait for events from all the spawned processes. Currently
     * waiting for child exit event only. But since we have the pipes setup as
     * IPC between the master and each of the child processes, we can make 
     * use of the same for sending any commands to child processes and
     * receiving events from child processes.
     */

    /**
     * TODO - if a single worker process dies, then fork and recreate that
     * specific instance of worker process (either signaling or db).
     */
    options = WEXITED;
    if (waitid(P_ALL, 0, &siginfo, options) == -1)
    {
        ICE_LOG(LOG_SEV_ALERT, 
                "Master process: unable to wait for the child processes");
    }

    printf("MASTER: OUT of wait loop\n");

    /** TODO - need to handle events from the webapp as well */


    /** TODO - kill all worker processes */
    for (i = 0; i < MB_ICE_SERVER_NUM_WORKER_PROCESSES; i++)
        kill(gaps_workers->workers[i].pid, SIGTERM);

    kill(g_mb_server.db_lookup.pid, SIGTERM);

    /** de-init turns, stun and transport */
    iceserver_deinit_stuns();
    iceserver_deinit_turns();
    iceserver_deinit_transport();

    /** TODO - close all sockets */

    /** TODO - close all message queues */
    mq_close(g_mb_server.qid_worker_db);
    mq_close(g_mb_server.qid_db_worker);
    mq_unlink(MQ_WORKER_DB);
    mq_unlink(MQ_DB_WORKER);

    closelog();

    return 0;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
