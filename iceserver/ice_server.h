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

#ifndef ICE_SERVER__H
#define ICE_SERVER__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

/** some configuration stuff */
#define MB_ICE_SERVER   "MindBricks ICE Server 0.1"

#define MB_ICE_SERVER_LISTEN_PORT   3478

#define MB_ICE_SERVER_TIMER_PORT    34343

#define NET_INTERFACE   "eth0"

#define MB_ICE_SERVER_USERNAME_LEN  128

#define MB_ICE_SERVER_REALM_LEN     128

#define MB_ICE_SERVER_HMAC_KEY_LEN  128

#define MB_ICE_SERVER_MAX_ALLOCATIONS   250

#define MB_ICE_SERVER_REASON_LENGTH 256

#define MB_ICE_SERVER_NONCE_EXPIRY  3600    /** secs */

#define MB_ICE_SERVER_DATA_SOCK_LIMIT   1024


typedef struct
{
    void *timer_id;
    void *arg;
} mb_ice_server_timer_event_t;


typedef enum
{
    MB_ISEVENT_NEW_ALLOC_REQ,
    MB_ISEVENT_DEALLOC_NOTF,
} mb_ice_server_event_t;


typedef struct
{
    mb_ice_server_event_t event;
    u_char username[MB_ICE_SERVER_USERNAME_LEN];
    u_char realm[MB_ICE_SERVER_REALM_LEN];
    uint32_t lifetime;
    stun_transport_protocol_type_t protocol;
    void *blob;
} mb_ice_server_new_alloc_t;


typedef struct
{
    handle blob;
    bool_t approved;
    uint32_t lifetime; /** in secs, if approved */
    uint32_t code;
    char reason[MB_ICE_SERVER_REASON_LENGTH];
    char hmac_key[MB_ICE_SERVER_HMAC_KEY_LEN];
} mb_ice_server_alloc_decision_t;


typedef struct
{
    int sockfd;

    struct sockaddr addr;

} mb_ice_server_intf_t;


typedef struct
{
    handle h_turns_inst;

    handle h_stuns_inst;

    pthread_t tid;

    /** internal communication between main thread and decision thread */
    int     thread_sockpair[2];

    int     timer_sockpair[2];

    fd_set  master_rfds;

    /** data sockets on which to listen */
    int relay_sockets[MB_ICE_SERVER_DATA_SOCK_LIMIT];
    int max_fd;

    mb_ice_server_intf_t intf[2];

} mb_ice_server_t;


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
