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

/** number of worker processes that handle the STUN/TURN traffic */
#define MB_ICE_SERVER_NUM_WORKER_PROCESSES  6

#define MB_ICE_MAX_ALLOCATIONS_COUNT    5000

#define MB_ICE_SERVER_MMAP_FILE_PATH    "/mbiceserver"


typedef struct
{
    void *timer_id;
    void *arg;
} mb_ice_server_timer_event_t;


typedef enum
{
    MB_ISEVENT_NEW_ALLOC_REQ = 0,
    MB_ISEVENT_DEALLOC_NOTF,
} mb_ice_server_event_type_t;


typedef struct
{
    mb_ice_server_event_type_t msg_type;
    u_char username[MB_ICE_SERVER_USERNAME_LEN];
    u_char realm[MB_ICE_SERVER_REALM_LEN];
    uint32_t lifetime;
    stun_transport_protocol_type_t protocol;
    handle h_alloc;
    handle app_blob;
    uint64_t ingress_bytes;
    uint64_t egress_bytes;
} mb_ice_server_event_t;


typedef struct
{
    handle blob;
    bool_t approved;
    uint32_t lifetime; /** in secs, if approved */
    uint32_t code;
    char reason[MB_ICE_SERVER_REASON_LENGTH];
    char hmac_key[MB_ICE_SERVER_HMAC_KEY_LEN];
    handle app_blob;
} mb_ice_server_alloc_decision_t;


typedef struct
{
    int op_type; /** 1 - add , 0 - remove */ /** TODO - can expand this? */
    int port;
} mb_ice_server_aux_data_t;


typedef struct
{
    int sockfd;
    struct sockaddr addr;
} mb_ice_server_intf_t;


typedef struct
{
    /** child pid */
    pid_t pid;

    /** communication between parent and child - pipe/socketpair? */
    int sockpair[2];  

} mb_iceserver_worker_t;


typedef struct
{
    mb_iceserver_worker_t workers[MB_ICE_SERVER_NUM_WORKER_PROCESSES];
} mb_iceserver_worker_list_t;


typedef struct
{
    //int relay_id;
    int relay_sock;
    int relay_port;
} mb_iceserver_relay_socket;


typedef struct
{
    handle h_turns_inst;
    handle h_stuns_inst;

    int timer_sockpair[2];

    /** data sockets on which to listen */
    //int relay_sockets[MB_ICE_SERVER_DATA_SOCK_LIMIT];
    mb_iceserver_relay_socket relays[MB_ICE_SERVER_DATA_SOCK_LIMIT];

#ifdef MB_USE_EPOLL
    /** epoll instance */
    int efd;
#else
    /** master fd set used for listening - used by signaling workers only */
    fd_set master_rfds;
    int max_fd;
#endif

    mb_ice_server_intf_t intf[2];

    /** database lookup process */
    mb_iceserver_worker_t db_lookup;

#if 0
    /** worker processes */
    mb_iceserver_worker_t workers[MB_ICE_SERVER_NUM_WORKER_PROCESSES];
#endif

    /** communication from worker processes to DB processes */
    mqd_t qid_worker_db;

    /** communication from DB processes to Worker processes */
    mqd_t qid_db_worker;

} mb_ice_server_t;


/** Function prototypes of the functions shared across the source files */
int32_t mb_ice_server_make_socket_non_blocking(int sock_fd);

int32_t iceserver_init_transport(void);

int32_t iceserver_deinit_transport(void);

int32_t iceserver_process_messages(mb_iceserver_worker_t *worker);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
