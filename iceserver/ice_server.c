/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
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

#include <stun_base.h>
#include <stun_enc_dec_api.h>
#include <turns_api.h>
#include <stuns_api.h>
#include <ice_server.h>


/** need to move the realm into configuration */
#define ICE_SERVER_REALM    "mindbricks.com"

char *log_levels[] =
{
    "LOG_SEV_CRITICAL",
    "LOG_SEV_ERROR",
    "LOG_SEV_WARNING",
    "LOG_SEV_INFO",
    "LOG_SEV_DEBUG",
};


/** the global instance of server */ 
mb_ice_server_t g_mb_server = {0};
stun_log_level_t g_loglevel = LOG_SEV_WARNING;

void *mb_iceserver_decision_thread(void);


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


    va_start(args, format );
    sprintf(buff, "| %s | %i msec <%s: %i> %s\n", 
            log_levels[level], relative_time, file_name, line_num, format);
    vprintf(buff, args );
    va_end(args );
}


void ice_server_timer_expiry_cb (void *timer_id, void *arg)
{
    ssize_t bytes = 0;
    mb_ice_server_timer_event_t timer_event;

    printf("[MB ICE SERVER] in sample application timer callback %d %p\n", 
            timer_id, arg);

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;

    bytes = send(g_mb_server.timer_sockpair[1], 
            (u_char *)&timer_event, sizeof(timer_event), 0);
    if (bytes == -1)
        printf("Error: Sending of timer event failed\n");
    
    return;
}



int32_t ice_server_network_send_data(u_char *data, 
        uint32_t data_len, stun_inet_addr_type_t ip_addr_type, 
        u_char *ip_addr, uint32_t port, handle transport_param, u_char *key)
{
    int32_t status, sent_bytes = 0;
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
            printf("inet_pton failed\n");
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
        printf ("Sending of STUN message failed\n");
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
            printf("inet_pton failed\n");
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
    printf("Now need to listen on this socket as well: %d\n", sock_fd);

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

    printf("ice_server: starting timer for duration %d "\
            "Argument is %p\n", duration, arg);

    timer_id = platform_start_timer(duration, timer_cb, arg);

    printf("timer id returned is %p\n", timer_id);

    return timer_id;
}



int32_t ice_server_stop_timer (handle timer_id)
{
    printf("ice_server: stopping timer %p\n", timer_id);

    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


int32_t ice_server_new_allocation_request(
                handle h_alloc, turns_new_allocation_params_t *alloc_req)
{
    int size, bytes = 0;
    mb_ice_server_new_alloc_t data;

    printf("[][][][][][][] NEW ALLOCATION REQUEST RECEIVED [][][][][][][]\n");

    memset(&data, 0, sizeof(data));

    /** 
     * This is messy! passing data between processes - 
     * need to find an elegant solution 
     */
    memcpy(data.username, alloc_req->username, alloc_req->username_len);
    memcpy(data.realm, alloc_req->realm, alloc_req->realm_len);
    data.lifetime = alloc_req->lifetime;
    data.protocol = alloc_req->protocol;
    data.blob = alloc_req->blob;
    
    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main socket listener thread. So post
     * this allocation request message to the slave thread that will
     * decide whether the allocation is to be approved or not.
     */
    bytes = send(g_mb_server.thread_sockpair[0], &data, sizeof(data), 0);
    printf ("Sent [%d] bytes to decision process\n", bytes);

    return STUN_OK;
}


int32_t ice_server_handle_events(turns_event_t event, handle h_alloc)
{
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
    event_cbs.alloc_event_cb = ice_server_handle_events;

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
    printf("Run Lola run\n");

    while (true)
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
        printf ("process socketpair() returned error\n");
        return STUN_INT_ERROR;
    }

    printf("Added decision process socket: %d to fd_set\n", 
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
        printf ("timer socketpair() returned error\n");
        return STUN_INT_ERROR;
    }

    /** add internal socket used for communication with the timer thread */
    FD_SET(g_mb_server.timer_sockpair[0], &g_mb_server.master_rfds);
    if (g_mb_server.max_fd < g_mb_server.timer_sockpair[0])
        g_mb_server.max_fd = g_mb_server.timer_sockpair[0];
    printf("Added timer thread socket: %d to fd_set\n", 
                                        g_mb_server.timer_sockpair[0]);

    if (platform_init() != true)
        return STUN_INT_ERROR;

    return STUN_OK;
}



int main (int argc, char *argv[])
{
    printf ("Hello world! This is MindBricks ICE server reporting for duty\n");

    iceserver_init();

    /** initialize the turns module */
    iceserver_init_turns();

    /** initialize the stuns module */
    iceserver_init_stuns();

    /** initialize the transport module */
    if (iceserver_init_transport() != STUN_OK)
    {
        printf("Initialization of transport failed\n");
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


    return 0;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
