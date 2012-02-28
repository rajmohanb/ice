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

#ifndef STUN_TXN_API__H
#define STUN_TXN_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define STUN_TXN_DEFAULT_RTO_DURATION           500     /** milliseconds */
#define STUN_TXN_DEFAULT_RTO_STALE_DURATION     10      /** minutes */
#define STUN_TXN_DEFAULT_RETX_COUNT             7
#define STUN_TXN_DEFAULT_RM_TIMER_COUNT         16
#define STUN_TXN_DEFAULT_OVERALL_TIMER          39500   /** milliseconds */

/******************************************************************************/


typedef int32_t (*stun_txn_nwk_send_cb) (handle h_msg, handle h_param);
typedef handle (*stun_txn_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*stun_txn_stop_timer_cb) (handle timer_id);


typedef enum {
    STUN_CLIENT_TXN = 0,
    STUN_SERVER_TXN = 1,
    STUN_TXN_TYPE_MAX = 2,
} stun_txn_type_t;


typedef enum {
    STUN_UNRELIABLE_TRANSPORT = 0,
    STUN_RELIABLE_TRANSPORT = 1,
} stun_transport_type_t;


typedef struct {
    stun_txn_nwk_send_cb nwk_cb;
    stun_txn_start_timer_cb start_timer_cb;
    stun_txn_stop_timer_cb  stop_timer_cb;
} stun_txn_instance_callbacks_t;


/******************************************************************************/

int32_t stun_txn_create_instance(uint32_t max_txns, handle *h_inst);

int32_t stun_txn_instance_set_callbacks(handle h_inst, 
                                        stun_txn_instance_callbacks_t *cb);

int32_t stun_txn_destroy_instance(handle h_inst);

int32_t stun_create_txn(handle h_inst, stun_txn_type_t type, 
                            stun_transport_type_t tport, handle *h_txn);

int32_t stun_txn_set_app_transport_param(handle h_inst, 
                                            handle h_txn, handle h_param);

int32_t stun_txn_set_app_param(handle h_inst, handle h_txn, handle h_param);


int32_t stun_txn_get_app_param(handle h_inst, handle h_txn, handle *h_param);


int32_t stun_txn_timer_set_handle(handle h_timer, handle timer_handle);


int32_t stun_txn_timer_get_handle(handle h_timer, handle *timer_handle);


int32_t stun_destroy_txn(handle h_inst, 
                        handle h_txn, bool_t keep_req, bool_t keep_resp);

int32_t stun_txn_inject_received_msg (handle h_inst, 
                                                handle h_txn, handle h_msg);

int32_t stun_txn_instance_find_transaction(handle h_inst, 
                                                handle h_msg, handle *h_txn);

int32_t stun_txn_send_stun_message(handle h_inst, handle h_txn, handle h_msg);

int32_t stun_txn_inject_timer_message(handle h_timerid,
                                        handle h_timer_arg, handle *h_txn);

int32_t stun_txn_timer_get_txn_handle(handle h_timer, 
                                            handle *h_txn, handle *h_txn_inst);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
