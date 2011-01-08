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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_txn_api.h"
#include "stun_txn_int.h"
#include "stun_txn_fsm.h"

static stun_txn_fsm_handler 
    stun_txn_fsm[STUN_TXN_FSM_MAX_STATE][STUN_EVENT_MAX] =
{
    /** STUN_OG_TXN_IDLE */
    {
        ignore_msg,
        send_req,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
    },
    /** STUN_OG_TXN_TRYING */
    {
        ignore_msg,
        ignore_msg,
        process_resp,
        resend_req,
        ignore_msg,
        terminate_txn,
    },
    /** STUN_OG_TXN_PROCEEDING */
    {
        ignore_msg,
        ignore_msg,
        process_resp,
        ignore_msg,
        terminate_txn,
        terminate_txn,
    },
    /** STUN_OG_TXN_TERMINATED */
    {
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
    },
    /** STUN_IC_TXN_IDLE */
    {
        ignore_msg,
        recv_req,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        terminate_txn,
    },
    /** STUN_IC_TXN_WAITING */
    {
        ignore_msg,
        ignore_msg,
        send_resp,
        ignore_msg,
        ignore_msg,
        terminate_txn,
    },
    /** STUN_IC_TXN_COMPLETED */
    {
        ignore_msg,
        send_resp,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        terminate_txn,
    },
    /** STUN_IC_TXN_TERMINATED */
    {
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
        ignore_msg,
    }
};



int32_t send_req (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    txn_ctxt->h_req = h_msg;

    txn_ctxt->instance->nwk_send_cb(h_msg, txn_ctxt->app_transport_param);

    if (txn_ctxt->tport == STUN_UNRELIABLE_TRANSPORT)
    {
        txn_ctxt->h_rto_timer = txn_ctxt->instance->start_timer_cb(
                                txn_ctxt->instance->rto, txn_ctxt->rto_params);
        ICE_LOG (LOG_SEV_INFO, "RTO timer handle %p\n", txn_ctxt->h_rto_timer);

        txn_ctxt->rc_count += 1;
        txn_ctxt->last_rto = txn_ctxt->instance->rto; 
    }
    else
    {
        txn_ctxt->h_overall_timer = 
            txn_ctxt->instance->start_timer_cb(
                    txn_ctxt->instance->overall_timer, txn_ctxt->oall_params);
        ICE_LOG (LOG_SEV_INFO, "Overall Ti timer handle for reliable transport %p\n", 
                                                    txn_ctxt->h_overall_timer);
    }

    txn_ctxt->h_req = h_msg;

    txn_ctxt->state = STUN_OG_TXN_TRYING;

    return STUN_OK;
}



int32_t process_resp (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    int32_t status;
    txn_ctxt->h_resp = h_msg;

    if (txn_ctxt->tport == STUN_UNRELIABLE_TRANSPORT)
    {
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rto_timer);
        if (status == STUN_OK) txn_ctxt->h_rto_timer = NULL;

        if (txn_ctxt->h_rm_timer)
        {
            status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rm_timer);
            if (status == STUN_OK) txn_ctxt->h_rm_timer = NULL;
        }
    }
    else
    {
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_overall_timer);
        if (status == STUN_OK) txn_ctxt->h_overall_timer = NULL;
    }

    return STUN_TERMINATED;
}



int32_t resend_req (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    txn_ctxt->instance->nwk_send_cb(txn_ctxt->h_req, 
                                        txn_ctxt->app_transport_param);

    txn_ctxt->rc_count += 1;

    if (txn_ctxt->tport == STUN_UNRELIABLE_TRANSPORT)
    {
        if (txn_ctxt->rc_count >= STUN_TXN_DEFAULT_RETX_COUNT)
        {
            uint32_t rm_timer = 
                txn_ctxt->instance->rm_timer * txn_ctxt->instance->rto;

            txn_ctxt->h_rm_timer = txn_ctxt->instance->start_timer_cb(
                                                rm_timer, txn_ctxt->rm_params);
            ICE_LOG (LOG_SEV_DEBUG, "RM timer handle %p\n", txn_ctxt->h_rto_timer);

            txn_ctxt->state = STUN_OG_TXN_PROCEEDING;
        }
        else
        {
            uint32_t new_rto = 2 * txn_ctxt->last_rto;
            txn_ctxt->h_rto_timer = txn_ctxt->instance->start_timer_cb(
                                                new_rto, txn_ctxt->rto_params);
            ICE_LOG (LOG_SEV_DEBUG, "RTO timer handle %p\n", txn_ctxt->h_rto_timer);

            txn_ctxt->last_rto = new_rto; 
        }
    }

    return STUN_OK;
}



int32_t terminate_txn (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    ICE_LOG (LOG_SEV_DEBUG, "RM timer expired.. returning STUN_TERMINATED\n");
    txn_ctxt->state = STUN_OG_TXN_TERMINATED;
    return STUN_TERMINATED;
}



int32_t send_resp (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    /** TODO - timers and state and stuff */

    txn_ctxt->h_resp = h_msg;
    txn_ctxt->instance->nwk_send_cb(txn_ctxt->h_resp, 
                                        txn_ctxt->app_transport_param);
    return STUN_OK;
}



int32_t recv_req (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    /** TODO - what else? */

    txn_ctxt->h_req = h_msg;
    txn_ctxt->state = STUN_IC_TXN_WAITING;

    return STUN_OK;
}



int32_t ignore_msg (stun_txn_context_t *txn_ctxt, handle h_msg)
{
    return STUN_OK;
}



int32_t stun_txn_fsm_inject_msg(stun_txn_context_t *txn_ctxt, 
                                    stun_txn_event_t event, handle h_msg)
{
    stun_txn_fsm_handler handler;

    handler = stun_txn_fsm[txn_ctxt->state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    return handler(txn_ctxt, h_msg);
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
