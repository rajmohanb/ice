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

#ifndef STUN_TXN_FSM__H
#define STUN_TXN_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t send_req (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t process_resp (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t resend_req (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t rm_timeout (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t overall_timeout (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t terminate_txn (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t send_resp (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t recv_req (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t ignore_msg (stun_txn_context_t *txn_ctxt, handle h_msg);

int32_t stun_txn_fsm_inject_msg(stun_txn_context_t *txn_ctxt, 
                                    stun_txn_event_t event, handle h_msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
