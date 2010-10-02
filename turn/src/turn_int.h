/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2010, MindBricks Technologies               *
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


typedef enum
{
    /** timer started by turn transactions */
    TURN_STUN_TXN_TIMER = 0,
    
    /** timers internal to turn */
    TURN_ALLOC_REFRESH_TIMER,
    TURN_BIND_REFRESH_TIMER,

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
    TURN_DATA_IND,
    TURN_TXN_TIMEOUT,
    TURN_DEALLOC_REQ,
    TURN_ALLOC_REFRESH_EXPIRY,
    TURN_EVENT_MAX,
} turn_event_t;


typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    /** session list */
    handle  h_table;

    turn_session_nwk_send_cb nwk_send_cb;
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

} turn_session_t;


typedef int32_t (*turn_session_fsm_handler) 
                    (turn_session_t *session, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
