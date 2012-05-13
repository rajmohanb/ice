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
#include <stun_enc_dec_api.h>
#include <turns_api.h>
#include <ice_server.h>


extern mb_ice_server_t g_mb_server;


#define MB_ICE_SERVER_LISTEN_PORT   3478
static int sockfd_arrary[2] = {0, 0};



int32_t mb_ice_server_get_local_interface(void)
{
    struct ifaddrs *ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    int count = 0;

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

        sockfd_arrary[count] = 
            socket(ifa->ifa_addr->sa_family, SOCK_DGRAM, 0);
        if (sockfd_arrary[count] == -1) goto MB_ERROR_EXIT;

        count++;
        if (bind(sockfd_arrary[count-1], 
                            ifa->ifa_addr, sizeof(struct sockaddr)) == -1)
        {
            perror("Bind");
            printf("Binding to interface failed [%s:%d]\n", 
                            ifa->ifa_name, ifa ->ifa_addr->sa_family);
            close(sockfd_arrary[count-1]);
            sockfd_arrary[count-1] = 0;
            //goto MB_ERROR_EXIT;
        }
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

    printf("Socket fd: [%d]\n", sockfd_arrary[0]);
    printf("Socket fd: [%d]\n", sockfd_arrary[1]);
    return STUN_OK;

MB_ERROR_EXIT:

    while(count > 0) { close(sockfd_arrary[count]); count--; }
    return STUN_TRANSPORT_FAIL;
}


int32_t iceserver_init_transport(void)
{
    return mb_ice_server_get_local_interface();
}



void mb_ice_server_process_signaling_msg(int fd)
{
    int bytes;
    int32_t status;
    char buf[1500];
    struct sockaddr client;
    handle h_rcvdmsg = NULL;
    turns_rx_stun_pkt_t pkt;
    socklen_t addrlen = sizeof(client);

    bytes = recvfrom(fd, buf, 1500, 0, &client, &addrlen);
    if (bytes == -1) return;
    if (bytes == 0) return;

    /** determine if this is a valid stun packet or not */
    status = turns_verify_valid_stun_packet((u_char *)buf, bytes);
    if (status == STUN_MSG_NOT) return;

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

    /** hand over to the turns module for further processing */
    status = turns_inject_received_msg(g_mb_server.h_turns_inst, &pkt);

    printf("Received signaling message of length [%d] bytes\n", bytes);

    return;
}



void mb_ice_server_process_media_msg(void)
{
    return;
}



int32_t iceserver_process_messages(void)
{
    int i, ret, max_fd;
    fd_set rfds;

    FD_ZERO(&rfds);
    max_fd = 0;

    /** add main signaling listener sockets */
    for(i = 0; i < 2; i++)
    {
        if (sockfd_arrary[i]) FD_SET(sockfd_arrary[i], &rfds);
        if (max_fd < sockfd_arrary[i]) max_fd = sockfd_arrary[i];
    }
 
    max_fd += 1;
    /** TODO LATER - add media sockets */

    //printf("About to enter pselect max_fd - %d\n", max_fd);
    ret = pselect(max_fd, &rfds, NULL, NULL, NULL, NULL);
    if (ret == -1)
    {
        perror("pselect");
        sleep(10);
        return STUN_TRANSPORT_FAIL;
    }
    //printf("After pselect %d\n", ret);

    for (i = 0; i < ret; i++)
    {
        if (FD_ISSET(sockfd_arrary[0], &rfds))
            mb_ice_server_process_signaling_msg(sockfd_arrary[0]);
        else if (FD_ISSET(sockfd_arrary[1], &rfds))
            mb_ice_server_process_signaling_msg(sockfd_arrary[1]);
        else
            mb_ice_server_process_media_msg();
    }

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/

