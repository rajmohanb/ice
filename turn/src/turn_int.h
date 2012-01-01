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

#ifndef TURN_INT__H
#define TURN_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



typedef struct
{
    uint32_t len;
    u_char *data;

    stun_inet_addr_t *dest;
} turn_app_data_t;


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
} turn_timer_params_t;


typedef enum 
{
    TURN_ALLOC_REQ = 0,
    TURN_ALLOC_RESP,
    TURN_CREATE_PERM_REQ,
    TURN_CREATE_PERM_RESP,
    TURN_REFRESH_REQ,
    TURN_REFRESH_RESP,
    TURN_SEND_IND,
    TURN_DATA_IND,
    TURN_TXN_TIMEOUT,
    TURN_DEALLOC_REQ,
    TURN_ALLOC_REFRESH_EXPIRY,
    TURN_PERM_REFRESH_EXPIRY,
    TURN_CHNL_REFRESH_EXPIRY,
    TURN_KEEP_ALIVE_EXPIRY,
    TURN_EVENT_MAX,
} turn_event_t;


typedef struct
{
    stun_inet_addr_t peer_addr;

#if 0
    /** use data/send indications or channels for media data */
    bool_t use_channel;
#endif

    /** handle to refresh permission by using channel bind */
    handle   h_perm_chnl_refresh;
    turn_timer_params_t *perm_chnl_refresh_timer_params;

    handle h_chnl_txn;
    handle h_chnl_req;
    handle h_chnl_resp;

} turn_permission_t;


typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    /** session list */
    handle  h_table;

    /** software client name and version */
    uint32_t client_name_len;
    u_char *client_name;

    turn_session_nwk_send_cb nwk_send_cb;
    turn_session_rx_app_data rx_data_cb;
    turn_session_start_timer_cb start_timer_cb;
    turn_session_stop_timer_cb stop_timer_cb;
    turn_session_state_change_cb state_change_cb;

    handle ah_session[TURN_MAX_CONCURRENT_SESSIONS];

} turn_instance_t;


typedef struct 
{
    turn_instance_t *instance;

    turn_session_state_t state;

    turn_server_cfg_t cfg;

    handle app_param;
    handle transport_param;

    handle h_txn;
    handle h_req;
    handle h_resp;

    /** nonce */
    uint32_t nonce_len;
    u_char *nonce;

    /** realm */
    uint32_t realm_len;
    u_char *realm;

    /** relayed address */
    stun_inet_addr_t relay_addr;

    /** server reflexive mapped address */
    stun_inet_addr_t mapped_addr;

    /** allocation expiry time in seconds */
    uint32_t lifetime;

    /** handle to allocation refresh timer */
    handle   h_alloc_refresh;
    turn_timer_params_t *alloc_refresh_timer_params;

    /** permission creation/refresh mode */
    turn_perm_method_t perm_method;
    
    /** list of permissions */
    turn_permission_t *aps_perms[TURN_MAX_PERMISSIONS];

    /** permission refresh timer */
    handle   h_perm_refresh;
    turn_timer_params_t *perm_refresh_timer_params;

    handle h_perm_txn;
    handle h_perm_req;
    handle h_perm_resp;

    /** Keep-Alive timer and related stuff */
    handle   h_keep_alive;
    turn_timer_params_t *keep_alive_timer_params;

    uint16_t channel_num;

} turn_session_t;


typedef int32_t (*turn_session_fsm_handler) 
                    (turn_session_t *session, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
