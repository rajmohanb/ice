/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2011, MindBricks Technologies               *
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

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <msg_layer_api.h>
#include <stun_enc_dec_api.h>
#include <stun_txn_api.h>

//#define STUN_SRV_IP "198.65.166.165"
//#define STUN_SRV_IP "75.101.138.128"
#define STUN_SRV_IP "216.146.46.55"
#define STUN_SRV_PORT 3478

handle h_txn_inst, h_txn;

handle stun_malloc(uint32_t size)
{
    return malloc(size);
}

handle stun_memset(handle s, int c, size_t n)
{
    return memset(s, c, n);
}

handle stun_memcpy(handle dest, handle src, uint32_t n)
{
    return memcpy(dest, src, n);
}

uint32_t stun_memcmp(handle s1, handle s2, u_int32 n)
{
    return memcmp(s1, s2, n);
}

void stun_free(handle obj)
{
    free(obj);
}

int main (int argc, char *argv[])
{
    handle h_msg, h_attr, h_rcvdmsg, ah_attr[5];
    int32_t status, len, num_attrs;
    u_char *buf, address[16];
    int sockfd, addrlen, bytes, num;
    struct sockaddr_in stun_srvr;
    enum_stun_method_type method;
    enum_stun_msg_type class_type;

    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_BINDING, &h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_create() returned error %d\n", status);
    else
        printf ("stun_msg_create() succeeded\n");

    status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_attr);
    if (status != STUN_OK)
        printf ("stun_attr_create() returned error %d\n", status);
    else
        printf ("stun_attr_create() succeeded\n");

    status = stun_attr_software_set_value(h_attr, "oooooooooo Technologies STUN stack 1.0");
    if (status != STUN_OK)
        printf ("stun_attr_software_set_value() returned error %d\n", status);
    else
        printf ("stun_attr_software_set_value() succeeded\n");

#if 0
    status = stun_msg_add_attribute(h_msg, h_attr);
    if (status != STUN_OK)
        printf ("stun_msg_add_attribute() returned error %d\n", status);
    else
        printf ("stun_msg_add_attribute() succeeded\n");
#endif

    status = stun_txn_create_instance(&h_txn_inst);
    if (status != STUN_OK)
        printf ("stun_txn_create_instance() returned error %d\n", status);
    else
        printf ("stun_txn_create_instance() succeeded\n");

    status = stun_create_txn(h_txn_inst, STUN_CLIENT_TXN, &h_txn);
    if (status != STUN_OK)
        printf ("stun_create_txn() returned error %d\n", status);
    else
        printf ("stun_create_txn() succeeded\n");

    buf = (u_char *) malloc(600);
    strcpy(buf, "something junk to start about");

    status = stun_msg_encode(h_msg, buf, (uint32_t *)&len);
    if (status != STUN_OK)
        printf ("stun_msg_format() returned error %d\n", status);
    else
        printf ("stun_msg_format() succeeded\n");

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    printf ("socket descriptor is %d\n", sockfd);

    memset((char *) &stun_srvr, 0, sizeof(stun_srvr));
    stun_srvr.sin_family = AF_INET;
    stun_srvr.sin_port = htons(STUN_SRV_PORT);
    if (inet_aton(STUN_SRV_IP, &stun_srvr.sin_addr)==0) {
        printf("inet_aton() failed\n");
        exit(1);
    }

    addrlen = sizeof(stun_srvr);

    bytes = sendto(sockfd, buf, len, 0, &stun_srvr, addrlen);
    printf ("sent %d bytes\n", bytes);

    status = stun_msg_destroy(h_msg);
    if (status != STUN_OK)
        printf ("stun_msg_destroy() returned error %d\n", status);
    else
        printf ("stun_msg_destroy() succeeded\n");


    printf ("**************************************************************\n");

    bytes = recvfrom(sockfd, buf, 600, 0, &stun_srvr, &addrlen);
    printf("Received packet from %s:%d\nData: %s\n\n", 
        inet_ntoa(stun_srvr.sin_addr), ntohs(stun_srvr.sin_port), buf);

    status = stun_msg_decode(buf, bytes, &h_rcvdmsg);
    if (status != STUN_OK)
        printf ("stun_msg_decode() returned error %d\n", status);
    else
        printf ("stun_msg_decode() succeeded\n");

    stun_msg_get_method(h_rcvdmsg, &method);
    stun_msg_get_class(h_rcvdmsg, &class_type);
    stun_msg_get_num_attributes(h_rcvdmsg, &num_attrs);

    printf ("received message method is %d and class is %d\n", method, class_type);
    printf ("number of attributes in received message: %d\n", num_attrs);

    num = 5;
    status = stun_msg_get_specified_attributes(
                    h_rcvdmsg, STUN_ATTR_MAPPED_ADDR, ah_attr, &num);
    if (status != STUN_OK)
        printf ("stun_msg_get_specified_attributes() returned error %d\n", status);
    else
        printf ("stun_msg_get_specified_attributes() succeeded\n");

    num = 16;
    status = stun_attr_mapped_addr_get_addres(ah_attr[0], address, &num);
    if (status != STUN_OK)
        printf ("stun_attr_mapped_addr_get_addres() returned error %d\n", status);
    else
        printf ("stun_attr_mapped_addr_get_addres() succeeded\n");

    printf ("So my MAPPED address is %s\n", address);

    return 0;
}
