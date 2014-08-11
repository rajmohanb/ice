/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2014, MindBricks Technologies               *
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

#include <pthread.h>
#include <errno.h>

#ifdef MB_USE_EPOLL
#include <sys/epoll.h>
#endif

#include <stun_base.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <stuns_api.h>
#include <turns_api.h>
#include <ice_server.h>


extern mb_ice_server_t g_mb_server;


int32_t mb_ice_server_make_socket_non_blocking(int sock_fd)
{
    int flags, s;

    flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
        return STUN_TRANSPORT_FAIL;
    }

    flags |= O_NONBLOCK;

    s = fcntl(sock_fd, F_SETFL, flags);
    if (s == -1)
    {
        perror("fcntl F_SETFL");
        return STUN_TRANSPORT_FAIL;
    }

    return STUN_OK;
}



int32_t mb_ice_server_get_local_interface(void)
{
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    int s, count = 0;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (strncmp(ifa->ifa_name, "lo", 2) == 0) continue;
        if (!ifa->ifa_addr) continue;

        if (ifa->ifa_addr->sa_family==AF_INET)
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

        ICE_LOG(LOG_SEV_ERROR, "**[LOCAL INTERAFCE] %d [LOCAL INTERAFCE]***\n", s);

        if (mb_ice_server_make_socket_non_blocking(s) != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Making the socket [%d] NON-BLOCKing failed", s);
            continue;
        }

        if (bind(s, ifa->ifa_addr, sizeof(struct sockaddr)) == -1)
        {
            perror("Bind");
            ICE_LOG(LOG_SEV_ERROR, "Binding to interface failed [%s:%d]", 
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

    if (ifAddrStruct != NULL) freeifaddrs(ifAddrStruct);

    ICE_LOG(LOG_SEV_DEBUG, "Socket fd: [%d]", g_mb_server.intf[0].sockfd);
    ICE_LOG(LOG_SEV_DEBUG, "Socket fd: [%d]", g_mb_server.intf[1].sockfd);
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
#ifndef MB_USE_EPOLL
    /** reset */
    g_mb_server.max_fd = 0;
    FD_ZERO(&g_mb_server.master_rfds);
#endif

    memset(g_mb_server.relays, 0, 
            (sizeof(mb_iceserver_relay_socket) * MB_ICE_SERVER_DATA_SOCK_LIMIT));

    return mb_ice_server_get_local_interface();
}



int32_t iceserver_deinit_transport(void)
{
    /** close the listening sockets */
    if (g_mb_server.intf[0].sockfd) close(g_mb_server.intf[0].sockfd);
    if (g_mb_server.intf[1].sockfd) close(g_mb_server.intf[1].sockfd);

    return STUN_OK;
}



void mb_ice_server_process_signaling_msg(mb_ice_server_intf_t *intf)
{
    int bytes;
    int32_t status;
    char buf[1500];
    struct sockaddr client;
    handle h_rcvdmsg = NULL;
    socklen_t addrlen = sizeof(client);

    do
    {
        bytes = recvfrom(intf->sockfd, buf, 1500, 0, &client, &addrlen);
    } while((bytes == -1) && (errno == EINTR));

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

        data.data = (u_char *)buf;
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
                                    g_mb_server.h_turns_inst, &data);
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
            status = stuns_inject_received_msg(
                    g_mb_server.h_stuns_inst, (stuns_rx_stun_pkt_t *)&pkt);
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
            status = turns_inject_received_msg(g_mb_server.h_turns_inst, &pkt);
        }
    }

    return;
}



#ifdef MB_USE_EPOLL
void mb_ice_server_process_media_msg(int event_fd)
#else
void mb_ice_server_process_media_msg(fd_set *read_fds)
#endif
{
    int bytes, i, sock_fd;
    char buf[1500] = {0};
    struct sockaddr client;
    socklen_t addrlen = sizeof(client);
    turns_rx_channel_data_t data;

    for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
        if (g_mb_server.relays[i].relay_sock)
#ifdef MB_USE_EPOLL
            if (event_fd == g_mb_server.relays[i].relay_sock)
#else
            if (FD_ISSET(g_mb_server.relays[i].relay_sock, read_fds))
#endif
                break;

    if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
    {
#ifdef MB_USE_EPOLL
        ICE_LOG(LOG_SEV_CRITICAL, "UDP data received on unknown socket %d? "\
                "This should not happen. Look into this", event_fd);
#else
        ICE_LOG(LOG_SEV_CRITICAL, "UDP data received on unknown socket? "\
                "This should not happen. Look into this");
#endif
        return;
    }

    sock_fd = g_mb_server.relays[i].relay_sock;

    do
    {
        bytes = recvfrom(sock_fd, buf, 1500, 0, &client, &addrlen);
    } while((bytes == -1) && (errno == EINTR));

    if (bytes == -1) return;

    /** check for EAGAIN or EWOULDBLOCK since the sockets are non blocking? */

    /** TODO - connection closed for TCP, remove the socket from list? */
    if (bytes == 0) return;

    data.data = (u_char *)buf;
    data.data_len = bytes;
    data.transport_param = (handle)sock_fd;
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

    turns_inject_received_udp_msg(g_mb_server.h_turns_inst, &data);

    return;
}


void mb_ice_server_process_timer_event(int fd)
{
    int32_t bytes;
    mb_ice_server_timer_event_t timer_event;

    bytes = recv(g_mb_server.timer_sockpair[0], 
                &timer_event, sizeof(timer_event), 0);
    if (bytes == -1)
    {
        ICE_LOG(LOG_SEV_ERROR, "Receiving of timer event failed");
        return;
    }

    ICE_LOG(LOG_SEV_ERROR, "Timer expired: ID %p ARG %p", 
            timer_event.timer_id, timer_event.arg);

    turns_inject_timer_event(timer_event.timer_id, timer_event.arg);

    return;
}


void mb_ice_server_process_approval(mqd_t mqdes)
{
    int32_t bytes;
    mb_ice_server_alloc_decision_t *resp;
    struct mq_attr attr;
    char *buffer = NULL;
    turns_allocation_decision_t turns_resp;

    /** TODO - need to optimize so that we do not allocate memory every time */

    mq_getattr(mqdes, &attr);
    buffer = (char *) stun_malloc(attr.mq_msgsize);

    do
    {
        bytes = mq_receive(mqdes, buffer, attr.mq_msgsize, 0);
    } while((bytes == -1) && (errno == EINTR));

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

    turns_inject_allocation_decision(
                        g_mb_server.h_turns_inst, (void *)&turns_resp);

    free(buffer);
    return;
}



void mb_ice_server_process_nwk_wakeup_event(int fd)
{
    int n;
    char tmpbuf;

    ICE_LOG(LOG_SEV_ERROR, "PID: %d Waking up from network event", getpid());

    n = read(fd, &tmpbuf, sizeof(tmpbuf));
    if (n <= -1)
    {
        perror("Network Wakeup Read");
        ICE_LOG(LOG_SEV_ERROR, 
                "Reading from network wakeup event socket failed");
        return;
    }

    return;
}



static int32_t mb_ice_server_process_control_info(int fd)
{
    int bytes, i;
    struct msghdr msgh;
    struct iovec iov[1];
    struct cmsghdr *cmsgp = NULL;
    char buf[CMSG_SPACE(sizeof(int))];
    mb_ice_server_aux_data_t aux_data;

    //pid_t mypid = getpid();
#ifdef MB_USE_EPOLL
    int s;
    struct epoll_event event;
#endif

    /** TODO - are these really necessary? performance? */
    memset(&msgh, 0, sizeof(msgh));
    memset(buf, 0, sizeof(buf));

    /** because we are making use of stream/connected sockets */
    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 1;

    /** initialize I/O vector to read data into our structure */
    iov[0].iov_base = (char *) &aux_data;
    iov[0].iov_len = sizeof(aux_data);

    msgh.msg_control = buf;
    msgh.msg_controllen = sizeof(buf);

    do
    {
        bytes = recvmsg(fd, &msgh, 0);
    } while((bytes == -1) && (errno == EINTR));

    if (bytes == -1)
    {
        perror("recvmsg :");
        return STUN_TRANSPORT_FAIL;
    }

    //printf("Auxillary data : op_type:%d port:%d\n", 
    //                        aux_data.op_type, aux_data.port);

    if (aux_data.op_type == 1)
    {
        /** walk thru the control structure looking for a socket descriptor */
        for (cmsgp = CMSG_FIRSTHDR(&msgh); 
                cmsgp != NULL; cmsgp = CMSG_NXTHDR(&msgh, cmsgp))
        {
            if (cmsgp->cmsg_level == SOL_SOCKET && 
                                cmsgp->cmsg_type == SCM_RIGHTS)
            {
                int rcvd_fd = *(int *) CMSG_DATA(cmsgp); 
                ICE_LOG(LOG_SEV_ALERT,
                        "Received ancillary file descriptor: %d", rcvd_fd);

                //printf("worker %d: Add aux socket %d\n", mypid, rcvd_fd);

                /** add it to the list */
                for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
                    if (g_mb_server.relays[i].relay_sock == 0)
                    {
                        g_mb_server.relays[i].relay_sock = rcvd_fd;
                        g_mb_server.relays[i].relay_port = aux_data.port;

                        break;
                    }

                if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
                {
                    ICE_LOG(LOG_SEV_ERROR, "Ran out of available relay "\
                            "sockets!!! Could not add the received ancillary "\
                            "socket descriptor %d to relay socket list", 
                            rcvd_fd);
                    return STUN_NO_RESOURCE;
                }

#ifdef MB_USE_EPOLL
                event.data.fd = rcvd_fd;
                event.events = EPOLLIN; // | EPOLLET;

                s = epoll_ctl(g_mb_server.efd, EPOLL_CTL_ADD, rcvd_fd, &event);
                if (s == -1)
                {
                    perror("epoll_ctl add");
                    return STUN_TRANSPORT_FAIL;
                }
#else
                FD_SET(rcvd_fd, &g_mb_server.master_rfds);
                if (g_mb_server.max_fd < rcvd_fd) g_mb_server.max_fd = rcvd_fd;
#endif
            }
        }
    }
    else if (aux_data.op_type == 0)
    {
        ICE_LOG(LOG_SEV_ALERT,
                "Need to remove ancillary file descriptor for port: %d", 
                aux_data.port);

        //printf("worker %d: Remove aux socket %d\n", mypid, aux_data.sock_fd);

        /** close and remove the socket from the list */
        for (i = 0; i < MB_ICE_SERVER_DATA_SOCK_LIMIT; i++)
            if (g_mb_server.relays[i].relay_port == aux_data.port)
            {
                int tmp_sock = g_mb_server.relays[i].relay_sock;

                g_mb_server.relays[i].relay_sock = 0;
                g_mb_server.relays[i].relay_port = 0;

#ifdef MB_USE_EPOLL
                event.data.fd = tmp_sock;
                event.events = EPOLLIN; // | EPOLLET;

                s = epoll_ctl(g_mb_server.efd, EPOLL_CTL_DEL, tmp_sock, &event);
                if (s == -1)
                {
                    perror("epoll_ctl del");
                    return STUN_TRANSPORT_FAIL;
                }
#else
                FD_CLR(tmp_sock, &g_mb_server.master_rfds);

                /** re-calculate the max fd, painful job */
                if (g_mb_server.max_fd == tmp_sock)
                    g_mb_server.max_fd = ice_server_get_max_fd();
#endif

                /** close the relay socket */
                close(tmp_sock);

                break;
            }

        if (i == MB_ICE_SERVER_DATA_SOCK_LIMIT)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Trying to remove socket fd for port: %d from the relay sock "\
                "queue. But could not locate it within the relay sock list", 
                aux_data.port);
            return STUN_NOT_FOUND;
        }
    }
    else
    {
        ICE_LOG(LOG_SEV_CRITICAL,
                "Some unknown ancillary data operation %d received", 
                aux_data.op_type);
        return STUN_INT_ERROR;
    }

    return STUN_OK;
}



#ifdef MB_USE_EPOLL
int32_t iceserver_process_messages(mb_iceserver_worker_t *worker)
{
    #define MB_EPOLL_MAX_EVENTS 64
    int i, nfds;
    struct epoll_event events[MB_EPOLL_MAX_EVENTS];

    //ICE_LOG(LOG_SEV_DEBUG, 
    //        "About to enter pselect max_fd - %d", (g_mb_server.max_fd+1));

    nfds = epoll_pwait(g_mb_server.efd, events, MB_EPOLL_MAX_EVENTS, -1, NULL);
    ICE_LOG(LOG_SEV_DEBUG, "epoll_pwait returned %d fds", nfds);

    if (nfds == -1 && errno == EINTR) return STUN_OK;
    if (nfds == -1)
    {
        perror("epoll_pwait");
        return STUN_TRANSPORT_FAIL;
    }

    for (i = 0; i < nfds; i++)
    {
        int event_fd = events[i].data.fd;

        if (event_fd == g_mb_server.intf[0].sockfd)
            mb_ice_server_process_signaling_msg(&g_mb_server.intf[0]);
        else if(event_fd == g_mb_server.intf[1].sockfd)
            mb_ice_server_process_signaling_msg(&g_mb_server.intf[1]);
        else if (event_fd == g_mb_server.qid_db_worker)
            mb_ice_server_process_approval(g_mb_server.qid_db_worker);
        else if (event_fd == g_mb_server.timer_sockpair[0])
            mb_ice_server_process_timer_event(event_fd);
        else if (event_fd == worker->sockpair[0])
            mb_ice_server_process_control_info(event_fd);
        else
#ifdef MB_USE_EPOLL
            mb_ice_server_process_media_msg(event_fd);
#else
            mb_ice_server_process_media_msg(&rfds);
#endif
    }

    return STUN_OK;
}
#else
int32_t iceserver_process_messages(mb_iceserver_worker_t *worker)
{
    int i, ret;
    fd_set rfds;

    /** make a copy of the read socket fds set */
    rfds = g_mb_server.master_rfds;

    //ICE_LOG(LOG_SEV_DEBUG, 
    //        "About to enter pselect max_fd - %d", (g_mb_server.max_fd+1));

    ret = pselect((g_mb_server.max_fd + 1), &rfds, NULL, NULL, NULL, NULL);

    ICE_LOG(LOG_SEV_DEBUG, "After pselect %d", ret);

    if (ret == -1 && errno == EINTR) return STUN_OK;

    if (ret == -1)
    {
        perror("pselect");
        return STUN_TRANSPORT_FAIL;
    }

    for (i = 0; i < ret; i++)
    {
        if (FD_ISSET(g_mb_server.intf[0].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(&g_mb_server.intf[0]);
        else if (FD_ISSET(g_mb_server.intf[1].sockfd, &rfds))
            mb_ice_server_process_signaling_msg(&g_mb_server.intf[1]);
        else if (FD_ISSET(g_mb_server.qid_db_worker, &rfds))
            mb_ice_server_process_approval(g_mb_server.qid_db_worker);
        else if (FD_ISSET(g_mb_server.timer_sockpair[0], &rfds))
            mb_ice_server_process_timer_event(g_mb_server.timer_sockpair[0]);
        else if (FD_ISSET(worker->sockpair[0], &rfds))
            mb_ice_server_process_control_info(worker->sockpair[0]);
        else
            mb_ice_server_process_media_msg(&rfds);
    }

    return STUN_OK;
}
#endif


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

