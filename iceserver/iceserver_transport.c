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
#include <ifaddrs.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include <stun_base.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <turns_api.h>
#include <ice_server.h>


extern mb_ice_server_t g_mb_server;



int32_t mb_ice_server_get_local_interface(void)
{
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    int s, count = 0;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strncmp(ifa->ifa_name, "lo", 2) == 0) continue;

        if (ifa ->ifa_addr->sa_family==AF_INET)
        {
            ((struct sockaddr_in *)ifa->ifa_addr)->sin_port = 
                                        htons(MB_ICE_SERVER_LISTEN_PORT);
        } else if (ifa->ifa_addr->sa_family==AF_INET6)
        {
            ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_port = 
                                        htons(MB_ICE_SERVER_LISTEN_PORT);
        }
        else
        {
            continue;
        }

        s = socket(ifa->ifa_addr->sa_family, SOCK_DGRAM, 0);
        if (s == -1) continue;

        if (bind(s, ifa->ifa_addr, sizeof(struct sockaddr)) == -1)
        {
            perror("Bind");
            printf("Binding to interface failed [%s:%d]\n", 
                            ifa->ifa_name, ifa ->ifa_addr->sa_family);
            close(s);
        }
        else
        {
            memcpy(&(g_mb_server.intf[count].addr), 
                            ifa->ifa_addr, sizeof(struct sockaddr));
            g_mb_server.intf[count].sockfd = s;
            count++;
        }
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

    printf("Socket fd: [%d]\n", g_mb_server.intf[0].sockfd);
    printf("Socket fd: [%d]\n", g_mb_server.intf[1].sockfd);
    return STUN_OK;

MB_ERROR_EXIT:

    while(count > 0) { close(g_mb_server.intf[count].sockfd); count--; }
    return STUN_TRANSPORT_FAIL;
}



#if 0
int32_t mb_ice_server_init_timer_comm(void)
{
    int timer_sockfd;
    struct sockaddr loopback_addr;

    timer_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (timer_sockfd == -1) return -1;

    memset(&loopback_addr, 0, sizeof(loopback_addr));

    /** for loopback, look at the first address type to know - IPv4 or IPv6 */
    if (g_mb_server.intf[0].addr.sa_family == AF_INET)
    {
        loopback_addr.sin_family = AF_UNIX;
        //loopback_addr.sin_port = htons(MB_ICE_SERVER_TIMER_PORT);
        //loopback_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        //loopback_addr.sin_family = AF_UNIX;
        //loopback_addr.sin_port = htons(MB_ICE_SERVER_TIMER_PORT);
        //loopback_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

#if 0
    status = platform_bind_socket(demo_sockfds[1], 
            (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (status == -1)
    {
        APP_LOG (LOG_SEV_ERROR,
                "binding to port failed... perhaps port already being used?\n");
        return status;
    }
    demo_sockfds_count++;
#endif
  
    return STUN_OK;
}
#endif



int32_t iceserver_init_transport(void)
{
    int32_t status, i;

    status = mb_ice_server_get_local_interface();
    if (status != STUN_OK) return status;

    /** add main signaling listener sockets */
    for(i = 0; i < 2; i++)
    {
        if (g_mb_server.intf[i].sockfd)
            FD_SET(g_mb_server.intf[i].sockfd, &g_mb_server.master_rfds);
        if (g_mb_server.max_fd < g_mb_server.intf[i].sockfd)
            g_mb_server.max_fd = g_mb_server.intf[i].sockfd;
    }

    /** setup internal timer communication */
    // status = mb_ice_server_init_timer_comm();

    return status;
}



void mb_ice_server_process_signaling_msg(int fd)
{
    int bytes, temp;
    int32_t status;
    char buf[1500];
    struct sockaddr client;
    handle h_rcvdmsg = NULL;
    socklen_t addrlen = sizeof(client);

    bytes = recvfrom(fd, buf, 1500, 0, &client, &addrlen);
    if (bytes == -1) return;

    /** TODO - connection closed for TCP, remove the socket from list? */
    if (bytes == 0) return;

    /**
     * determine if this is a valid stun packet or not. Incase it is not
     * a stun message, it could also be channeldata message, which is used
     * by turn to relay data. In order to determine if the received message 
     * is a channel data message or a stun/turn message, one needs to look 
     * at the first 2 bits of the received message. 
     * rfc 5766: sec 11 Channels
     * 0b00: STUN-formatted message
     * 0b01: ChannelData message
     * 0b10: Reserved
     * 0b11: Reserved
     */
    if ((*buf & 0xc0) == 0x40)
    {
        turns_rx_channel_data_t data;

        printf("CHANNEL DATA message\n");

        data.data = buf;
        data.data_len = bytes;
        data.transport_param = (handle)fd;
        data.protocol = ICE_TRANSPORT_UDP;

        if(client.sa_family == AF_INET)
        {
            data.src.host_type = STUN_INET_ADDR_IPV4;
            data.src.port = ntohs(((struct sockaddr_in *)&client)->sin_port);
            inet_ntop(AF_INET, &(((struct sockaddr_in *)&client)->sin_addr), 
                    (char *)data.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
        }
        else if(client.sa_family == AF_INET6)
        {
            data.src.host_type = STUN_INET_ADDR_IPV6;
            data.src.port = ntohs(((struct sockaddr_in6 *)&client)->sin6_port);
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&client)->sin6_addr),
                    (char *)data.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
        }

        status = turns_inject_received_channeldata_msg(
                                    g_mb_server.h_turns_inst, &data);
    }
    else if ((*buf & 0xc0) == 0xc0)
    {
        printf("Future reserved, Dropping\n");
    }
    else
    {
        turns_rx_stun_pkt_t pkt;
        stun_method_type_t method;
        stun_msg_type_t msg_type;

        /** otherwise this is a stun/turn message */
        status = turns_verify_valid_stun_packet((u_char *)buf, bytes);
        if (status == STUN_MSG_NOT) return;

        printf("\n\nReceived signaling message of length [%d] bytes\n", bytes);

        /** decode the message */
        status = stun_msg_decode((u_char *)buf, bytes, false, &h_rcvdmsg);
        if (status != STUN_OK)
        {
            printf("stun_msg_decode() returned error %d\n", status);
            return;
        }

        pkt.h_msg = h_rcvdmsg;
        pkt.transport_param = (handle)fd;
        pkt.protocol = ICE_TRANSPORT_UDP;

        if(client.sa_family == AF_INET)
        {
            pkt.src.host_type = STUN_INET_ADDR_IPV4;
            pkt.src.port = ntohs(((struct sockaddr_in *)&client)->sin_port);
            inet_ntop(AF_INET, &(((struct sockaddr_in *)&client)->sin_addr), 
                    (char *)pkt.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
        }
        else if(client.sa_family == AF_INET6)
        {
            pkt.src.host_type = STUN_INET_ADDR_IPV6;
            pkt.src.port = ntohs(((struct sockaddr_in6 *)&client)->sin6_port);
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&client)->sin6_addr),
                    (char *)pkt.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
        }

        status = stun_msg_get_method(h_rcvdmsg, &method);
        status = stun_msg_get_class(h_rcvdmsg, &msg_type);

        if((method == STUN_METHOD_BINDING) && (msg_type == STUN_REQUEST))
        {
            /** hand over to the stun server module */
            status = stuns_inject_received_msg(g_mb_server.h_stuns_inst, &pkt);
        }
        else
        {
            /** hand over to the turns module for further processing */
            status = turns_inject_received_msg(g_mb_server.h_turns_inst, &pkt);
        }
    }

    return;
}



void mb_ice_server_process_media_msg(fd_set *read_fds)
{
    int32_t status;
    int bytes, i, sock_fd;
    char buf[1500] = {0};
    struct sockaddr client;
    socklen_t addrlen = sizeof(client);
    turns_rx_channel_data_t data;

    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relay_sockets[i])
            if (FD_ISSET(g_mb_server.relay_sockets[i], read_fds))
                break;

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
        printf("UDP data received on unknown socket? "\
                "This should not happen. Look into this\n");
        return;
    }

    sock_fd = g_mb_server.relay_sockets[i];
 
    bytes = recvfrom(sock_fd, buf, 1500, 0, &client, &addrlen);
    if (bytes == -1) return;

    /** TODO - connection closed for TCP, remove the socket from list? */
    if (bytes == 0) return;

    data.data = buf;
    data.data_len = bytes;
    data.transport_param = sock_fd;
    data.protocol = ICE_TRANSPORT_UDP;

    if(client.sa_family == AF_INET)
    {
        data.src.host_type = STUN_INET_ADDR_IPV4;
        data.src.port = ntohs(((struct sockaddr_in *)&client)->sin_port);
        inet_ntop(AF_INET, &(((struct sockaddr_in *)&client)->sin_addr), 
                (char *)data.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
    }
    else if(client.sa_family == AF_INET6)
    {
        data.src.host_type = STUN_INET_ADDR_IPV6;
        data.src.port = ntohs(((struct sockaddr_in6 *)&client)->sin6_port);
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&client)->sin6_addr),
                (char *)data.src.ip_addr, ICE_IP_ADDR_MAX_LEN);
    }

    status = turns_inject_received_udp_msg(g_mb_server.h_turns_inst, &data);

    return;
}


void mb_ice_server_process_timer_event(int fd)
{
    int32_t bytes, status;
    mb_ice_server_timer_event_t timer_event;

    bytes = recv(g_mb_server.timer_sockpair[0], 
                &timer_event, sizeof(timer_event), 0);
    if (bytes == -1)
        printf("Receiving of timer event failed\n");

    printf("Timer expired: ID %p ARG %p\n", 
            timer_event.timer_id, timer_event.arg);

    status = turns_inject_timer_event(timer_event.timer_id, timer_event.arg);

    return;
}


void mb_ice_server_process_approval(int fd)
{
    int32_t bytes, status;
    mb_ice_server_alloc_decision_t resp;

    bytes = recv(g_mb_server.thread_sockpair[0], &resp, sizeof(resp), 0);
    if (bytes == -1) return;
    if (bytes == 0) return;

    /** 
     * TODO - The 'mb_ice_server_alloc_decision_t' must be converted to 
     * 'turns_allocation_decision_t' before injecting. But for now using 
     * the same since both the structures have same contents 
     */

    status = turns_inject_allocation_decision(
                        g_mb_server.h_turns_inst, (void *)&resp);

    return;
}



int32_t iceserver_process_messages(void)
{
    int i, ret;
    fd_set rfds;

    /** make a copy of the read socket fds set */
    rfds = g_mb_server.master_rfds;
    printf("About to enter pselect max_fd - %d\n", (g_mb_server.max_fd+1));

    ret = pselect((g_mb_server.max_fd + 1), &rfds, NULL, NULL, NULL, NULL);
    if (ret == -1)
    {
        perror("pselect");
        return STUN_TRANSPORT_FAIL;
    }
    printf("After pselect %d\n", ret);

    for (i = 0; i < ret; i++)
    {
        if (FD_ISSET(g_mb_server.intf[0].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(g_mb_server.intf[0].sockfd);
        else if (FD_ISSET(g_mb_server.intf[1].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(g_mb_server.intf[1].sockfd);
        else if (FD_ISSET(g_mb_server.thread_sockpair[0], &rfds))
            mb_ice_server_process_approval(g_mb_server.thread_sockpair[0]);
        else if (FD_ISSET(g_mb_server.timer_sockpair[0], &rfds))
            mb_ice_server_process_timer_event(g_mb_server.timer_sockpair[0]);
        else
            mb_ice_server_process_media_msg(&rfds);
    }

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

