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


typedef enum
{
    /** timer started by turn transactions */
    TURN_STUN_TXN_TIMER = 0,
    
    /** timers internal to turn */
    TURN_ALLOC_REFRESH_TIMER,
    TURN_PERM_REFRESH_TIMER,
    TURN_CHNL_REFRESH_TIMER,
    TURN_KEEP_ALIVE_TIMER,

    /** that's all we have as of now */
} turn_timer_type_t;


typedef struct {
    handle h_instance;
    handle h_turn_session;
    turn_timer_type_t type;
    handle timer_id;
    handle arg;
} turns_timer_params_t;


typedef enum
{
    TSALLOC_CHALLENGED = 0,
    TSALLOC_PENDING,
    TSALLOC_CREATED,
    TSALLOC_STATE_MAX,
} turns_alloc_state_t;


typedef enum 
{
    TURNS_ALLOC_REQ = 0,
    TURNS_ALLOC_APPROVED,
    TURNS_ALLOC_REJECTED,
    TURNS_ALLOC_EVENT_MAX,
} turns_alloc_event_t;


typedef struct
{
    stun_inet_addr_t peer_addr;

#if 0
    /** use data/send indications or channels for media data */
    bool_t use_channel;
#endif

    /** handle to refresh permission by using channel bind */
    handle   h_perm_chnl_refresh;
    turns_timer_params_t *perm_chnl_refresh_timer_params;

    handle h_chnl_txn;
    handle h_chnl_req;
    handle h_chnl_resp;

} turn_permission_t;


typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    /** list of allocations */
    handle  h_table;

    /** software client name and version */
    uint32_t client_name_len;
    u_char *client_name;

    /** realm */
    uint32_t realm_len;
    char *realm;

    /** timer and socker callbacks */
    turns_nwk_send_cb nwk_send_cb;
    turns_start_timer_cb start_timer_cb;
    turns_stop_timer_cb stop_timer_cb;

    /** event callbacks */
    turns_new_alloc_cb new_alloc_cb;
    turns_alloc_event_cb alloc_event_cb;

} turns_instance_t;


typedef struct 
{
    turns_instance_t *instance;

    turns_alloc_state_t state;

    /******/ 

    /** client's server-reflexive transport address */    
    stun_inet_addr_t client_addr;

    /** server's transport address */
    handle transport_param;

    /** transport protocol */
    stun_transport_protocol_type_t protocol;
    
    /******/ 

    /** nonce */
    u_char nonce[TURNS_SERVER_NONCE_LEN];

    /** username */
    uint32_t username_len;
    u_char *username;

    /** requested transport */
    stun_transport_protocol_type_t req_tport;

    /** 
     * allocation expiry time in seconds. initially when the allocation 
     * context is created this might hold the lifetime requested by the
     * client, but gets overwritten by the server application decided value.
     */
    uint32_t lifetime;

    /******/ 

    handle app_param;

    handle h_txn;
    handle h_req;
    handle h_resp;

    /** relayed address */
    stun_inet_addr_t relay_addr;

    /** server reflexive mapped address */
    stun_inet_addr_t mapped_addr;


    /** handle to allocation refresh timer */
    handle   h_alloc_refresh;
    turns_timer_params_t *alloc_refresh_timer_params;

    /** permission creation/refresh mode */
    //turn_perm_method_t perm_method;
    
    /** list of permissions */
    turn_permission_t *aps_perms[TURN_MAX_PERMISSIONS];

    /** permission refresh timer */
    handle   h_perm_refresh;
    turns_timer_params_t *perm_refresh_timer_params;

    handle h_perm_txn;
    handle h_perm_req;
    handle h_perm_resp;

    /** Keep-Alive timer and related stuff */
    handle   h_keep_alive;
    turns_timer_params_t *keep_alive_timer_params;

    uint16_t channel_num;

} turns_allocation_t;



typedef int32_t (*turns_alloc_fsm_handler) 
            (turns_allocation_t *alloc, handle h_msg);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
