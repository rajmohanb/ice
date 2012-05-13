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
#include <turns_api.h>
#include <ice_server.h>


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

void *mb_iceserver_decision_thread(void *arg);


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
#if 0
    static int32_t sock = 0;
    ice_demo_timer_event_t timer_event;

    APP_LOG (LOG_SEV_DEBUG,
            "[ICE_AGENT_DEMO] in sample application timer callback %d %p", timer_id, arg);

    if (sock == 0)
    {
        sock = platform_create_socket(AF_INET, SOCK_DGRAM, 0);
        if(sock == -1)
        {
            APP_LOG(LOG_SEV_CRITICAL, "[ICE AGENT DEMO] Timer event socket creation failed");
            return;
        }
    }

    timer_event.timer_id = timer_id;
    timer_event.arg = arg;

    platform_socket_sendto(sock, 
                (u_char *)&timer_event, sizeof(timer_event), 0, 
                AF_INET, ICE_SERVER_INTERNAL_TIMER_PORT, g_localip);
#endif
    
    return;
}


int32_t ice_server_network_send_msg(handle h_msg, 
        stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
        uint32_t port, handle transport_param, handle app_param)
{
    int sent_bytes = 0;
#if 0
    int sock_fd = (int) param;

    if (ip_addr_type == STUN_INET_ADDR_IPV4)
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET, port, (char *)ip_addr);
    }
    else if (ip_addr_type == STUN_INET_ADDR_IPV6)
    {
        sent_bytes = platform_socket_sendto(sock_fd, buf, 
                            buf_len, 0, AF_INET6, port, (char *)ip_addr);
    }
    else
    {
        app_log (LOG_SEV_INFO, __FILE__, __LINE__,
                "[ICE AGENT DEMO] Invalid IP address family type. "\
                "Sending of STUN message failed");
    }
#endif

    return sent_bytes;
}


handle ice_server_start_timer (uint32_t duration, handle arg)
{
    timer_expiry_callback timer_cb = ice_server_timer_expiry_cb;

    return platform_start_timer(duration, timer_cb, arg);
}


int32_t ice_server_stop_timer (handle timer_id)
{
    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


int32_t ice_server_new_allocation_request(handle h_alloc)
{
    printf("[][][][][][][][] NOW ALLOCATION REQUEST RECEIVED [][][][][][][][]\n");

    /**
     * this callback routine must not consume too much time since it is 
     * running in the context of the main listener thread.
     */

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
    status = turns_create_instance(&(g_mb_server.h_turns_inst));
    if (status != STUN_OK) return status;

    status = turns_instance_set_server_software_name(
            g_mb_server.h_turns_inst, MB_ICE_SERVER, strlen(MB_ICE_SERVER));
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** set up os callbacks */
    osa_cbs.nwk_cb = ice_server_network_send_msg;
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

    return status;

MB_ERROR_EXIT:
    status = turns_destroy_instance(g_mb_server.h_turns_inst);
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
    int s;
    struct sockaddr_un local;
    char *ptr;

    memset(&local, 0, sizeof(struct sockaddr_un));

    strcpy(local.sun_path, "/tmp/");
    ptr = local.sun_path + strlen("/tmp/");
    if (platform_get_random_data((u_char *)ptr, 20) != true)
    {
        printf("error! unable to get random data\n");
        return STUN_INT_ERROR;
    }

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s == -1) return STUN_INT_ERROR;

    local.sun_family = AF_UNIX;
    unlink(local.sun_path);

    if (bind(s, (struct sockaddr *)&local, 
                sizeof(local.sun_path) + sizeof(local.sun_family)) == -1)
    {
        printf("Binding to unix domain socket failed\n");
        return STUN_INT_ERROR;
    }

    /** 
     * spin off a thread whose responsibility is to approve or deny any new 
     * allocation requests based on the set policies and quotas. This thread
     * is the point for enforcement of the local allocation policy.
     */
    if (pthread_create(&g_mb_server.tid, 
                NULL, mb_iceserver_decision_thread, (void *)s))
    {
        perror("pthread_create");
        printf("Thread creation failed\n");
        return STUN_INT_ERROR;
    }

    return STUN_OK;
}



int main (int argc, char *argv[])
{
    printf ("Hello world! This is MindBricks ICE server reporting for duty\n");

    iceserver_init();

    /** initialize the turns module */
    iceserver_init_turns();

    /** initialize the transport module */
    if (iceserver_init_transport() != STUN_OK)
    {
        printf("Initialization of transport failed\n");
        return -1;
    }

    /** the loop! */
    ice_server_run();

    return 0;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
