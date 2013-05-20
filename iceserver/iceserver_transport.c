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
#include <ifaddrs.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mqueue.h>

#include <errno.h>

#include <stun_base.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <turns_api.h>
#include <ice_server.h>


extern mb_ice_server_t *g_mb_server;



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
            ICE_LOG(LOG_SEV_ERROR, "Binding to interface failed [%s:%d]", 
                            ifa->ifa_name, ifa ->ifa_addr->sa_family);
            close(s);
        }
        else
        {
            memcpy(&(g_mb_server->intf[count].addr), 
                            ifa->ifa_addr, sizeof(struct sockaddr));
            g_mb_server->intf[count].sockfd = s;
            count++;
        }
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

    ICE_LOG(LOG_SEV_DEBUG, "Socket fd: [%d]", g_mb_server->intf[0].sockfd);
    ICE_LOG(LOG_SEV_DEBUG, "Socket fd: [%d]", g_mb_server->intf[1].sockfd);
    return STUN_OK;

MB_ERROR_EXIT:

    while(count > 0) { close(g_mb_server->intf[count].sockfd); count--; }
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
    if (g_mb_server->intf[0].addr.sa_family == AF_INET)
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



int32_t mb_ice_server_setup_nwk_wakeup_interface(void)
{
    int32_t status;

    if (socketpair(AF_UNIX, SOCK_STREAM, 
                        0, g_mb_server->nwk_wakeup_sockpair) == -1)
    {
        perror ("Network Wakeup Socketpair");
        ICE_LOG (LOG_SEV_ALERT, 
                "Network Wakeup Socketpair() returned error for DB process");
        return STUN_INT_ERROR;
    }

    return STUN_OK;
}



int32_t iceserver_init_transport(void)
{
    int32_t status, i;

    /** reset */
    g_mb_server->max_fd = 0;
    FD_ZERO(&g_mb_server->master_rfds);
    memset(g_mb_server->relay_sockets, 0, 
                (sizeof(int) * MB_ICE_SERVER_DATA_SOCK_LIMIT));

    status = mb_ice_server_get_local_interface();
    if (status != STUN_OK) return status;

    /** setup internal timer communication */
    // status = mb_ice_server_init_timer_comm();
    
    /** setup an interface to wake up worker tasks waiting on network events */
    status = mb_ice_server_setup_nwk_wakeup_interface();

    return status;
}



int32_t iceserver_deinit_transport(void)
{
    /** close the listening sockets */
    if (g_mb_server->intf[0].sockfd) close(g_mb_server->intf[0].sockfd);
    if (g_mb_server->intf[1].sockfd) close(g_mb_server->intf[1].sockfd);

    return STUN_OK;
}



void mb_ice_server_process_signaling_msg(mb_ice_server_intf_t *intf)
{
    int bytes, temp;
    int32_t status;
    char buf[1500];
    struct sockaddr client;
    handle h_rcvdmsg = NULL;
    socklen_t addrlen = sizeof(client);

    bytes = recvfrom(intf->sockfd, buf, 1500, 0, &client, &addrlen);
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

        ICE_LOG(LOG_SEV_DEBUG, "CHANNEL DATA message");

        data.data = buf;
        data.data_len = bytes;
        data.transport_param = (handle)intf->sockfd;
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
                                    g_mb_server->h_turns_inst, &data);
    }
    else if ((*buf & 0xc0) == 0xc0)
    {
        ICE_LOG(LOG_SEV_DEBUG, "Future reserved, Dropping");
    }
    else
    {
        turns_rx_stun_pkt_t pkt;
        stun_method_type_t method;
        stun_msg_type_t msg_type;

        /** otherwise this is a stun/turn message */
        status = turns_verify_valid_stun_packet((u_char *)buf, bytes);
        if (status == STUN_MSG_NOT) return;

        ICE_LOG(LOG_SEV_DEBUG, 
                "Received signaling message of length [%d] bytes", bytes);

        /** decode the message */
        status = stun_msg_decode((u_char *)buf, bytes, false, &h_rcvdmsg);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_WARNING, 
                    "stun_msg_decode() returned error %d", status);
            return;
        }

        pkt.h_msg = h_rcvdmsg;
        pkt.transport_param = (handle)intf->sockfd;
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
            status = stuns_inject_received_msg(g_mb_server->h_stuns_inst, &pkt);
        }
        else
        {
            /**
             * fill up the additional local interface details, which identifies 
             * the local interface on which the message was received on. 
             */
            if(intf->addr.sa_family == AF_INET)
            {
                pkt.local_intf.host_type = STUN_INET_ADDR_IPV4;
                pkt.local_intf.port = 
                    ntohs(((struct sockaddr_in *)&intf->addr)->sin_port);
                inet_ntop(AF_INET, 
                        &(((struct sockaddr_in *)&intf->addr)->sin_addr), 
                        (char *)pkt.local_intf.ip_addr, ICE_IP_ADDR_MAX_LEN);
            }
            else if(intf->addr.sa_family == AF_INET6)
            {
                pkt.local_intf.host_type = STUN_INET_ADDR_IPV6;
                pkt.local_intf.port = 
                    ntohs(((struct sockaddr_in6 *)&intf->addr)->sin6_port);
                inet_ntop(AF_INET6, 
                        &(((struct sockaddr_in6 *)&intf->addr)->sin6_addr),
                        (char *)pkt.local_intf.ip_addr, ICE_IP_ADDR_MAX_LEN);
            }

            /** hand over to the turns module for further processing */
            status = turns_inject_received_msg(g_mb_server->h_turns_inst, &pkt);
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

    pthread_rwlock_rdlock(&g_mb_server->socklist_lock);

    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server->relay_sockets[i])
            if (FD_ISSET(g_mb_server->relay_sockets[i], read_fds))
                break;

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
        ICE_LOG(LOG_SEV_CRITICAL, "UDP data received on unknown socket? "\
                "This should not happen. Look into this");
        return;
    }

    sock_fd = g_mb_server->relay_sockets[i];

    pthread_rwlock_unlock(&g_mb_server->socklist_lock);
 
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

    status = turns_inject_received_udp_msg(g_mb_server->h_turns_inst, &data);

    return;
}


void mb_ice_server_process_timer_event(int fd)
{
    int32_t bytes, status;
    mb_ice_server_timer_event_t timer_event;

    bytes = recv(g_mb_server->timer_sockpair[0], 
                &timer_event, sizeof(timer_event), 0);
    if (bytes == -1)
        ICE_LOG(LOG_SEV_ERROR, "Receiving of timer event failed");

    ICE_LOG(LOG_SEV_DEBUG, "Timer expired: ID %p ARG %p", 
            timer_event.timer_id, timer_event.arg);

    status = turns_inject_timer_event(timer_event.timer_id, timer_event.arg);

    return;
}


void mb_ice_server_process_approval(mqd_t mqdes)
{
    int32_t bytes, status;
    mb_ice_server_alloc_decision_t *resp;
    struct mq_attr attr;
    char *buffer = NULL;
    turns_allocation_decision_t turns_resp;

    /** TODO - need to optimize so that we do not allocate memory every time */

    mq_getattr(mqdes, &attr);
    buffer = (char *) stun_malloc(attr.mq_msgsize);

    bytes = mq_receive(mqdes, buffer, attr.mq_msgsize, 0);
    if (bytes == -1)
    {
        perror("Worker mq_receive");
        ICE_LOG(LOG_SEV_ERROR, "Worker Retrieving msg from msg queue failed");
        free(buffer);
        return;
    }

    if (bytes == 0) return;

    resp = (mb_ice_server_alloc_decision_t *) buffer;

    /** 
     * TODO - The 'mb_ice_server_alloc_decision_t' must be converted to 
     * 'turns_allocation_decision_t' before injecting. But for now using 
     * the same since both the structures have same contents 
     */
    turns_resp.blob = resp->blob;
    turns_resp.approved = resp->approved;
    turns_resp.lifetime = resp->lifetime;
    turns_resp.code = resp->code;
    strncpy(turns_resp.reason, resp->reason, TURNS_ERROR_REASON_LENGTH);
    memcpy(turns_resp.key, resp->hmac_key, 16);
    turns_resp.app_blob = resp->app_blob;

    status = turns_inject_allocation_decision(
                        g_mb_server->h_turns_inst, (void *)&turns_resp);

    free(buffer);
    return;
}



void mb_ice_server_process_nwk_wakeup_event(int fd)
{
    int n;
    char tmpbuf[1];

    ICE_LOG(LOG_SEV_ERROR, "PID: %d Waking up from network event", getpid());

    n = read(fd, tmpbuf, sizeof(tmpbuf));
    if (n <= -1)
    {
        perror("Network Wakeup Read");
        ICE_LOG(LOG_SEV_ERROR, 
                "Reading from network wakeup event socket failed");
        return;
    }

    return;
}



int32_t iceserver_process_messages(void)
{
    int i, ret;
    fd_set rfds;

    pthread_rwlock_rdlock(&g_mb_server->socklist_lock);

    /** make a copy of the read socket fds set */
    rfds = g_mb_server->master_rfds;
    ICE_LOG(LOG_SEV_DEBUG, 
            "About to enter pselect max_fd - %d", (g_mb_server->max_fd+1));

    ret = pselect((g_mb_server->max_fd + 1), &rfds, NULL, NULL, NULL, NULL);
    if (ret == -1)
    {
        perror("pselect");
        return STUN_TRANSPORT_FAIL;
    }
    ICE_LOG(LOG_SEV_DEBUG, "After pselect %d", ret);
    
    pthread_rwlock_unlock(&g_mb_server->socklist_lock);

    for (i = 0; i < ret; i++)
    {
        if (FD_ISSET(g_mb_server->intf[0].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(&g_mb_server->intf[0]);
        else if (FD_ISSET(g_mb_server->intf[1].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(&g_mb_server->intf[1]);
        else if (FD_ISSET(g_mb_server->qid_db_worker, &rfds))
            mb_ice_server_process_approval(g_mb_server->qid_db_worker);
        else if (FD_ISSET(g_mb_server->timer_sockpair[0], &rfds))
            mb_ice_server_process_timer_event(g_mb_server->timer_sockpair[0]);
        else if (FD_ISSET(g_mb_server->nwk_wakeup_sockpair[1], &rfds))
            mb_ice_server_process_nwk_wakeup_event(
                            g_mb_server->nwk_wakeup_sockpair[0]);
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

