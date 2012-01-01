/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                   MindBricks Confidential Proprietary.                       *
*                         All Rights Reserved.                                 *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/


/*******************************************************************************
*                                                                              *
* This sample application shows how the stun binding layer can be used as      *
* a keep-alive mechanism between the device and the network.                   *
*                                                                              *
*******************************************************************************/

//#define TEST_IPV6

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <stun_txn_api.h>
#include "stun_binding_api.h"


#ifdef TEST_IPV6
#define STUN_SRV_IP "2001:db8:0:242::67"
#else
//#define STUN_SRV_IP "192.168.1.2"
#define STUN_SRV_IP "208.97.25.20" // NO xor mapped addr
//#define STUN_SRV_IP "64.34.202.155" // YES xor mapped addr
#endif
#define STUN_SRV_PORT 3478

#define TRANSPORT_MTU_SIZE  1500

#define LOCAL_IP   "192.168.1.2"
#define LOCAL_STUN_HOST_PORT 33333


handle h_inst, h_session;
static int sockfd_stun = 0;
u_char *my_buf;
bool_t o_done = false;

char *stun_retval[] =
{
    "STUN_OK",
    "STUN_INT_ERROR",
    "STUN_MEM_ERROR",
    "STUN_INVALID_PARAMS",
    "STUN_NOT_FOUND",
    "STUN_TERMINATED",
    "STUN_PARSE_FAILED",
    "STUN_MEM_INSUF",
    "STUN_NOT_SUPPORTED",
    "STUN_TRANSPORT_FAIL",
    "STUN_VALIDATON_FAIL",
};


void app_log(stun_log_level_t level, char *format, ...)
{
    char buff[150];
    va_list args;
    va_start(args, format );
    sprintf(buff, "%s\n", format);
    vprintf(buff, args );
    va_end(args );
}


void app_timer_expiry_cb (void *timer_id, void *arg)
{
    int32_t status;
    handle bind_session;

    app_log (LOG_SEV_DEBUG, "in sample application timer callback");

    /** inject timer message */
    status = stun_binding_session_inject_timer_event(
                                        timer_id, arg, &bind_session);
    if (status == STUN_TERMINATED)
    {
        app_log (LOG_SEV_INFO, 
                "stun_binding_session_inject_timer_event() returned "\
                "failure: %s. STUN Binding session terminated due to timeout", 
                stun_retval[status]);
        o_done = true;
    }

    return;
}


int32_t app_nwk_send_msg (handle h_msg, 
        stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
        uint32_t port, handle transport_param, handle app_param)
{
    unsigned int sent_bytes, buf_len;
    int sock_fd = (int) transport_param;
    u_char *buf;
    int status;

    buf = (u_char *) platform_calloc(1, TRANSPORT_MTU_SIZE);

    status = stun_msg_encode(h_msg, NULL, buf, (uint32_t *)&buf_len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, "stun_msg_format() returned error: %s\n", 
                stun_retval[status]);
        return STUN_INT_ERROR;
    }

    sent_bytes = platform_socket_send(sock_fd, buf, buf_len, 0);

    platform_free(buf);
    return sent_bytes;
}

handle app_start_timer (uint32_t duration, handle arg)
{
    timer_expiry_callback timer_cb = app_timer_expiry_cb;

    return platform_start_timer(duration, timer_cb, arg);
}

int32_t app_stop_timer (handle timer_id)
{
    if (platform_stop_timer(timer_id) == true)
        return STUN_OK;
    else
        return STUN_NOT_FOUND;
}


bool app_initialize_stun_binding_layer(void)
{
    stun_binding_instance_callbacks_t app_cbs;
    int32_t status;

    status = stun_binding_create_instance(&h_inst);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR,
                "stun_binding_create_instance() returned error: %s\n", 
                stun_retval[status]);
        return false;
    }

    app_cbs.nwk_cb = app_nwk_send_msg;
    app_cbs.start_timer_cb = app_start_timer;
    app_cbs.stop_timer_cb = app_stop_timer;

    status = stun_binding_instance_set_callbacks(h_inst, &app_cbs);
    if (status != STUN_OK)
    {
        app_log (LOG_SEV_ERROR, 
                "stun_binding_instance_set_callbacks() returned error: %s\n", 
                stun_retval[status]);
        return false;
    }

    return true;
}


int main (int argc, char *argv[])
{
    handle h_rcvdmsg, h_target;
    int32_t status;
    unsigned int bytes, rv, count = 0;
    bool_t o_error = false;
    struct addrinfo hints, *servinfo, *p;
    char temp_port[10] = {0};
    stun_inet_addr_type_t addr_type;

    /** initialize platform library */
    platform_init();

#ifdef TEST_IPV6
    printf("Running in IPv6 mode...\n");
    addr_type = STUN_INET_ADDR_IPV6;
#else
    printf("Running in IPv4 mode...\n");
    addr_type = STUN_INET_ADDR_IPV4;
#endif

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    sprintf(temp_port, "%d", STUN_SRV_PORT);

    rv = getaddrinfo(STUN_SRV_IP, temp_port, &hints, &servinfo);
    if (rv) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    //-------------------------
    /** create a transport blob */
    
    /* loop through all the results and bind to the first we can */
    for(p = servinfo; p != NULL; p = p->ai_next) {

        if ((sockfd_stun = socket(p->ai_family, 
                            p->ai_socktype, p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (connect(sockfd_stun, p->ai_addr,  p->ai_addrlen) != 0) {
            close(sockfd_stun);
            perror("connect: ");
            continue;
        }

        break;
    }
   
    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    printf("listener: waiting to recvfrom...\n");
    
    app_log(LOG_SEV_DEBUG, 
            "Transport param for binding connection :-> %d", sockfd_stun);

    /** all ground work done, ready to use the stun binding apis */

    if (app_initialize_stun_binding_layer() == false)
    {
        app_log (LOG_SEV_ERROR, 
                "app_initialize_stun_binding_layer() returned error\n");
        return -1;
    }

    my_buf = (unsigned char *) platform_malloc (TRANSPORT_MTU_SIZE);

    while ((o_error == false) && (count < 100))
    {
        app_log (LOG_SEV_ERROR, "**************************************************************\n");

        status = stun_binding_create_session(h_inst, 
                                    STUN_BIND_CLIENT_SESSION, &h_session);
        if (status != STUN_OK)
        {
            app_log (LOG_SEV_ERROR, 
                    "stun_binding_create_session() returned error %d\n", 
                    stun_retval[status]);
            return -1;
        }

        status = stun_binding_session_set_transport_param(
                                        h_inst, h_session, (handle)sockfd_stun);
        if (status != STUN_OK)
        {
            app_log (LOG_SEV_ERROR, 
                    "stun_binding_session_set_transport_param() returned error %d\n", 
                    stun_retval[status]);
            return -1;
        }

        status = stun_binding_session_set_stun_server(
                h_inst, h_session, addr_type, (u_char *)STUN_SRV_IP, STUN_SRV_PORT);
        if (status != STUN_OK)
        {
            app_log (LOG_SEV_ERROR, 
                    "stun_binding_session_set_stun_server() returned error %d\n", 
                    stun_retval[status]);
            return -1;
        }

        status = stun_binding_session_send_message(h_inst, h_session, STUN_REQUEST);
        if (status != STUN_OK)
        {
            app_log (LOG_SEV_ERROR, 
                    "stun_binding_session_send_message() returned error %s\n", 
                    stun_retval[status]);
            return -1;
        }

        app_log (LOG_SEV_ERROR, "COUNT: %d\n", count);
        count++;

        /** if you have come so far, then the stun binding request has been sent */

        while (o_done == false)
        {
            bytes = platform_socket_recv(sockfd_stun, my_buf, TRANSPORT_MTU_SIZE, 0);

            if (bytes) break;
        }

        if (o_done == true) goto error_exit;
        if (bytes == -1) goto error_exit;

        status = stun_msg_decode(my_buf, bytes, true, &h_rcvdmsg);
        if (status != STUN_OK)
        {
            app_log (LOG_SEV_ERROR, "stun_msg_decode() returned error %d\n", 
                    stun_retval[status]);
            return -1;
        }

        status = stun_binding_instance_find_session_for_received_msg(
                                            h_inst, h_rcvdmsg, &h_target);
        if (status == STUN_NOT_FOUND)
        {
            app_log(LOG_SEV_ERROR, 
                    "No binding session found for received message on transport fd %d", sockfd_stun);
            o_error = true;
            stun_msg_destroy(h_rcvdmsg);
        }
        else if (status == STUN_OK)
        {
            stun_inet_addr_t mapped_addr;

            status = stun_binding_session_inject_received_msg(h_inst, h_target, h_rcvdmsg);
            if (status == STUN_TERMINATED)
            {
                status = stun_binding_session_get_xor_mapped_address(
                                            h_inst, h_target, &mapped_addr);
                if (status != STUN_OK)
                {
                    app_log(LOG_SEV_ERROR, 
                        "unable to get xor mapped address. Returned error: %s", 
                        stun_retval[status]);
                    o_error = true;
                }
                else
                {
                    app_log(LOG_SEV_ERROR, 
                            "\n\nXOR MAPPED ADDRESS and PORT : %s and %d\n\n", 
                            mapped_addr.ip_addr, mapped_addr.port);
                }

                status = stun_binding_session_get_mapped_address(
                                            h_inst, h_target, &mapped_addr);
                if (status != STUN_OK)
                {
                    app_log(LOG_SEV_ERROR, 
                        "unable to get mapped address. Returned error: %s", 
                        stun_retval[status]);
                    o_error = true;
                }
                else
                {
                    app_log(LOG_SEV_ERROR, 
                            "\n\nMAPPED ADDRESS and PORT : %s and %d\n\n", 
                            mapped_addr.ip_addr, mapped_addr.port);
                    sleep(1);
                }


                stun_binding_destroy_session(h_inst, h_session);
            }
            else if (status != STUN_OK)
            {
                app_log (LOG_SEV_ERROR, 
                        "stun_binding_session_inject_received_msg() returned error: %s\n", 
                        stun_retval[status]);
                o_error = true;

                stun_binding_destroy_session(h_inst, h_session);
            }
        }
    }

error_exit:
    stun_binding_destroy_instance(h_inst);
    platform_free(my_buf);

    platform_exit();

    return 0;
}
