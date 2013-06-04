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

#ifndef TURNS_INT__H
#define TURNS_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



#define TURNS_HMAC_KEY_LEN      16


typedef enum
{
    /** timer started by turn transactions */
    TURNS_STUN_TXN_TIMER = 0,
    
    /** timers internal to turn */
    TURNS_ALLOC_TIMER,
    TURNS_PERM_TIMER,
    TURNS_CHNL_TIMER,
    TURNS_NONCE_TIMER,

    /** that's all we have as of now */
} turns_timer_type_t;


typedef struct {
    handle h_instance;
    handle h_alloc;
    turns_timer_type_t type;
    handle timer_id;
    handle arg;
} turns_timer_params_t;


typedef enum
{
    TSALLOC_UNALLOCATED = 0,
    TSALLOC_CHALLENGED,
    TSALLOC_PENDING,
    TSALLOC_ALLOCATED,
    TSALLOC_TERMINATING,
    TSALLOC_STATE_MAX,
} turns_alloc_state_t;


typedef enum 
{
    TURNS_ALLOC_REQ = 0,
    TURNS_ALLOC_APPROVED,
    TURNS_ALLOC_REJECTED,
    TURNS_REFRESH_REQ,
    TURNS_ALLOC_TIMER_EXP,
    TURNS_PERM_REQ,
    TURNS_CHNL_BIND_REQ,
    TURNS_SEND_IND,
    TURNS_MEDIA_DATA,
    TURNS_NONCE_TIMER_EXP,
    TURNS_CHNL_BIND_TIMER_EXP,
    TURNS_PERM_TIMER_EXP,
    TURNS_CHNL_DATA_IND,
    TURNS_ALLOC_TERMINATE,
    TURNS_ALLOC_EVENT_MAX,
} turns_alloc_event_t;


typedef struct
{
    bool_t used;

    /** channel number TODO: this number should be 2 bytes? */
    uint32_t channel_num;

    /** transport address of the peer */
    stun_inet_addr_t peer_addr;

    /** handle to permission refresh timer */
    handle h_perm_timer;
    turns_timer_params_t perm_timer;

    /** handle to channel binding time-to-expiry timer */
    handle h_channel_timer;
    turns_timer_params_t channel_timer;

#if 0
    /** use data/send indications or channels for media data */
    bool_t use_channel;
#endif

    handle h_chnl_txn;
    handle h_chnl_req;
    handle h_chnl_resp;

} turns_permission_t;


typedef struct 
{
#ifndef MB_STATELESS_TURN_SERVER
    /** transaction instance handle */
    handle h_txn_inst;
#endif

    /** list of allocations */
    handle  h_table;

    /** software client name and version */
    uint32_t client_name_len;
    u_char *client_name;

    /** realm */
    uint32_t realm_len;
    char *realm;

    /** timer and socker callbacks */
    turns_nwk_send_data_cb nwk_data_cb;
    turns_nwk_send_stun_msg_cb nwk_stun_cb;
    turns_new_socket_cb new_socket_cb;
    turns_remove_socket_cb remove_socket_cb;
    turns_start_timer_cb start_timer_cb;
    turns_stop_timer_cb stop_timer_cb;

    /** event callbacks */
    turns_new_alloc_cb new_alloc_cb;
    turns_alloc_event_cb alloc_event_cb;

    /** current allocations */
    int num_allocs;

    /** maximum configured allocations */
    int max_allocs;

    /** nonce stale timer value in seconds */
    uint32_t nonce_timeout;

} turns_instance_t;


typedef struct 
{
    turns_instance_t *instance;

    turns_alloc_state_t state;

    /** client's server-reflexive transport address */    
    stun_inet_addr_t client_addr;

    /** server's transport address */
    handle transport_param;

    /** transport protocol */
    stun_transport_protocol_type_t protocol;
    
    /** nonce */
    u_char nonce[TURNS_SERVER_NONCE_LEN];

    /** username */
    uint32_t username_len;
    u_char username[TURN_MAX_USERNAME_LEN];

    /**
     * hmac key - will always be 16 bytes since 
     * md5 is used for long-terms authentication.
     */
    u_char hmac_key[TURNS_HMAC_KEY_LEN];

    /** requested transport */
    stun_transport_protocol_type_t req_tport;

    /** 
     * allocation expiry time in seconds. initially when the allocation 
     * context is created this might hold the lifetime requested by the
     * client, but gets overwritten by the server application decided value.
     */
    uint32_t lifetime;
    uint32_t initial_lifetime;

    /******/ 

    handle app_param;

    handle h_txn;
    handle h_req;
    handle h_resp;

    /** relayed address for this allocation on the server */
    stun_inet_addr_t relay_addr;
    int relay_sock;

    /** handle to allocation refresh timer */
    handle h_alloc_timer;
    turns_timer_params_t alloc_timer_params;

    /** stale nonce timer */
    handle h_nonce_timer;
    turns_timer_params_t nonce_timer_params;

    /** list of permissions */
    turns_permission_t aps_perms[TURNS_MAX_PERMISSIONS];

    /** application server blob identifier */
    handle app_blob;

    /** lock */
    pthread_mutex_t lock;

#ifdef MB_SMP_SUPPORT
    /** copy of stun message, required when interacting with decision process */
    uint32_t stun_msg_len;
    u_char  stun_msg[TURN_SERVER_MSG_CACHE_LEN];
#endif

} turns_allocation_t;



typedef int32_t (*turns_alloc_fsm_handler) 
            (turns_allocation_t *alloc, handle h_msg);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
