/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Copyright (C) 2009-2012, Rajmohan Banavi                    *
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

#ifndef STUN_TXN_INT__H
#define STUN_TXN_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef enum {
    STUN_EVENT_MIN = 0,
    STUN_REQ = 1,
    STUN_RESP = 2,
    RETRANS_TIMER = 3,
    RM_TIMER = 4,
    OVERALL_TIMER = 5,
    STUN_EVENT_MAX = 6,
} stun_txn_event_t;


typedef enum {
    STUN_OG_TXN_IDLE= 0,
    STUN_OG_TXN_TRYING = 1,
    STUN_OG_TXN_PROCEEDING = 2,
    STUN_OG_TXN_TERMINATED = 3,

    STUN_IC_TXN_IDLE = 4,
    STUN_IC_TXN_WAITING = 5,
    STUN_IC_TXN_COMPLETED = 6,
    STUN_IC_TXN_TERMINATED = 7,

    STUN_TXN_FSM_MAX_STATE = 8,
} stun_txn_fsm_state_t;


typedef enum {
    STUN_TXN_RTO_TIMER,
    STUN_TXN_RM_TIMER,
    STUN_TXN_OVERALL_TIMER,
    STUN_TXN_TIMER_MAX,
} stun_txn_timer_type_t;


typedef struct {
    handle h_instance;
    handle h_txn;
    stun_txn_timer_type_t type;
    handle timer_handle;
} stun_txn_timer_params_t;


typedef struct {
    uint32_t rto;
    uint32_t rto_lifetime;
    uint32_t retx_count;
    uint32_t rm_timer;
    uint32_t overall_timer;
    handle  h_table;
    stun_txn_nwk_send_cb nwk_send_cb;
    stun_txn_start_timer_cb start_timer_cb;
    stun_txn_stop_timer_cb stop_timer_cb;
} stun_txn_instance_t;



typedef struct {
    stun_txn_type_t txn_type;
    stun_txn_fsm_state_t state;
    stun_transport_type_t tport;

    handle h_rto_timer;
    stun_txn_timer_params_t *rto_params;
    handle h_rm_timer;
    stun_txn_timer_params_t *rm_params;
    handle h_overall_timer;
    stun_txn_timer_params_t *oall_params;

    u_char txn_id[STUN_TXN_ID_BYTES];

    stun_txn_instance_t *instance;

    handle h_req;
    handle h_resp;

    uint32_t rc_count;
    uint32_t last_rto;

    handle app_transport_param;
    handle app_param;

} stun_txn_context_t;



typedef int32_t (*stun_txn_fsm_handler) 
                    (stun_txn_context_t *txn_ctxt, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
