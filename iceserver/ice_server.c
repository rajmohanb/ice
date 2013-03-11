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

#include <syslog.h> /** logging */

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

static iceserver_signal_t signals_list[] =
{
    { SIGHUP, iceserver_sig_handler },
    { SIGINT, iceserver_sig_handler },
    { SIGQUIT, iceserver_sig_handler },
    { SIGILL, iceserver_sig_handler },
    { SIGABRT, iceserver_sig_handler },
    { SIGBUS, iceserver_sig_handler },
    { SIGSEGV, iceserver_sig_handler },
}; 


/** the global instance of server */ 
mb_ice_server_t g_mb_server = {0};
stun_log_level_t g_loglevel = LOG_SEV_WARNING;
int iceserver_quit = 0;

void *mb_iceserver_decision_thread(void);


static void iceserver_sig_handler(int signum)
{
    iceserver_quit = 1;
    printf("Quiting\n");
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


void ice_server_timer_expiry_cb (void *timer_id, void *arg)
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



int32_t ice_server_network_send_data(u_char *data, 
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
    if (sent_bytes == -1) perror("sendto");

    return sent_bytes;
}



int32_t ice_server_network_send_msg(handle h_msg, 
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
    if (sent_bytes == -1) perror("sendto");

    return sent_bytes;
}


int32_t ice_server_add_socket(handle h_alloc, int sock_fd) 
{
    int i;
    ICE_LOG(LOG_SEV_DEBUG, 
            "Now need to listen on this socket as well: %d", sock_fd);

    /** add it to the list */
    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i] == 0)
            g_mb_server.relay_sockets[i] = sock_fd;

    FD_SET(sock_fd, &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < sock_fd) g_mb_server.max_fd = sock_fd;

    /** need to wake up the waiting pselect */

    return STUN_OK;
}


handle ice_server_start_timer (uint32_t duration, handle arg)
{
    handle timer_id = NULL;

    timer_expiry_callback timer_cb = ice_server_timer_expiry_cb;

    ICE_LOG(LOG_SEV_WARNING, "ice_server: starting timer for duration %d "\
            "Argument is %p", duration, arg);

    timer_id = platform_start_timer(duration, timer_cb, arg);

    ICE_LOG(LOG_SEV_DEBUG, "timer id returned is %p", timer_id);

    return timer_id;
}



int32_t ice_server_stop_timer (handle timer_id)
{
    ICE_LOG(LOG_SEV_DEBUG, "ice_server: stopping timer %p", timer_id);

    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


int32_t ice_server_new_allocation_request(
                handle h_alloc, turns_new_allocation_params_t *alloc_req)
{
    int bytes = 0;
    mb_ice_server_event_t event;

    memset(&event, 0, sizeof(event));

    /** 
     * This is messy! passing data between processes - 
     * need to find an elegant solution 
     */
    event.type = MB_ISEVENT_NEW_ALLOC_REQ;
    memcpy(event.username, alloc_req->username, alloc_req->username_len);
    memcpy(event.realm, alloc_req->realm, alloc_req->realm_len);
    event.lifetime = alloc_req->lifetime;
    event.protocol = alloc_req->protocol;
    event.h_alloc = alloc_req->blob;
    
    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main socket listener thread. So post
     * this allocation request message to the slave thread that will
     * decide whether the allocation is to be approved or not.
     */
    bytes = send(g_mb_server.thread_sockpair[0], &event, sizeof(event), 0);
    ICE_LOG (LOG_SEV_DEBUG, "Sent [%d] bytes to decision process", bytes);

    return STUN_OK;
}


int32_t ice_server_handle_allocation_events(
            turns_event_t event, handle h_alloc, handle app_blob)
{
    int bytes = 0;
    mb_ice_server_event_t mb_event;

    ICE_LOG(LOG_SEV_DEBUG, 
            "Received allocation event for allocation %p: ", h_alloc);

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
    mb_event.type = MB_ISEVENT_DEALLOC_NOTF;
    mb_event.h_alloc = h_alloc;
    mb_event.app_blob = app_blob;
    
    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main socket listener thread. So post
     * this allocation request message to the slave thread that will
     * decide how to respond to the specific event.
     */
    bytes = send(g_mb_server.thread_sockpair[0], 
                                        &mb_event, sizeof(mb_event), 0);
    ICE_LOG (LOG_SEV_DEBUG, "Sent [%d] bytes to decision process", bytes);

    return STUN_OK;
}


int32_t iceserver_init_turns(void)
{
    int32_t status;
    turns_osa_callbacks_t osa_cbs;
    turns_event_callbacks_t event_cbs;

    /** initialize the turns module */
    status = turns_create_instance(25, 1, &(g_mb_server.h_turns_inst));
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
    osa_cbs.new_socket_cb = ice_server_add_socket;
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


int32_t iceserver_init_stuns(void)
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


void ice_server_run(void)
{
    ICE_LOG(LOG_SEV_DEBUG, "Run Lola run");

    while (!iceserver_quit)
    {
        iceserver_process_messages();
    }

    return;
}



int32_t iceserver_init(void)
{
    g_mb_server.max_fd = 0;
    FD_ZERO(&g_mb_server.master_rfds);
    memset(g_mb_server.relay_sockets, 0, 
                (sizeof(int) * MB_ICE_SERVER_DATA_SOCK_LIMIT));


    /** for comm between the approval process and main signaling process */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_mb_server.thread_sockpair) == -1)
    {
        perror ("process socketpair");
        ICE_LOG (LOG_SEV_ERROR, "process socketpair() returned error");
        return STUN_INT_ERROR;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Added decision process socket: %d to fd_set", 
                                        g_mb_server.thread_sockpair[0]);
    /** add internal socket used for communication with the decision process */
    FD_SET(g_mb_server.thread_sockpair[0], &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < g_mb_server.thread_sockpair[0])
        g_mb_server.max_fd = g_mb_server.thread_sockpair[0];

    /** 
     * for comm between the timer thread and the main signaling 
     * thread to notify about the timer expiry 
     * TODO: 
     * Here we do not need 2 way IPCs because the communication is always one
     * way since the timer thread will always notify the main signaling thread
     * about a timer expiry. However, currently we handle stopping of the 
     * timer expiry by directly looping into the linked list of timer nodes.
     * This might take too much time, in such a case, we might need to push
     * the timer stop operation into the timer thread?
     */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_mb_server.timer_sockpair) == -1)
    {
        perror ("timer socketpair");
        ICE_LOG (LOG_SEV_ERROR, "timer socketpair() returned error");
        return STUN_INT_ERROR;
    }

    /** add internal socket used for communication with the timer thread */
    FD_SET(g_mb_server.timer_sockpair[0], &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < g_mb_server.timer_sockpair[0])
        g_mb_server.max_fd = g_mb_server.timer_sockpair[0];
    ICE_LOG(LOG_SEV_DEBUG, "Added timer thread socket: %d to fd_set", 
                                        g_mb_server.timer_sockpair[0]);

    if (platform_init() != true)
        return STUN_INT_ERROR;

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



int main (int argc, char *argv[])
{
    int32_t status;
    printf ("MindBricks ICE server booting up...\n");

    /** daemonize */
    /** iceserver_daemonize(); */
    if (daemon(0, 0) == -1)
    {
        printf("Could not be daemonized\n");
        exit(-1);
    }

    /** set up logging */
    iceserver_init_log();
    ICE_LOG(LOG_SEV_ALERT, "MindBricks ICE server booting up...");

    /** init the signal handlers */
    iceserver_init_sig_handlers();

    iceserver_init();

    /** initialize the turns module */
    status = iceserver_init_turns();
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "ICE server initialization failed");
        ICE_LOG(LOG_SEV_ERROR, "Bailing out!!!");
        exit(1);
    }

    /** initialize the stuns module */
    iceserver_init_stuns();

    /** initialize the transport module */
    if (iceserver_init_transport() != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Initialization of transport failed");
        return -1;
    }

    if (!fork())
    {
        /** child */
        mb_iceserver_decision_thread();
    }
    else
    {
        /** parent - the loop! */
        ice_server_run();
    }

    closelog();

    return 0;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
