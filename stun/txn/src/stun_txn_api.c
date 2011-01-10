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
#include "stun_txn_table.h"
#include "stun_txn_utils.h"
#include "stun_txn_fsm.h"


    
int32_t stun_txn_create_instance(uint32_t max_txns, handle *h_inst)
{
    int32_t status;
    stun_txn_instance_t *instance;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (stun_txn_instance_t *) 
                        stun_calloc (1, sizeof(stun_txn_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    instance->rto = STUN_TXN_DEFAULT_RTO_DURATION;
    instance->rto_lifetime = STUN_TXN_DEFAULT_RTO_STALE_DURATION;
    instance->retx_count = STUN_TXN_DEFAULT_RETX_COUNT;
    instance->rm_timer = STUN_TXN_DEFAULT_RM_TIMER_COUNT;
    instance->overall_timer = STUN_TXN_DEFAULT_OVERALL_TIMER;

    status = stun_txn_create_table(max_txns, &(instance->h_table));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "stun transaction instance table creation failed");
        stun_free(instance);
    }
    else
    {
        *h_inst = (handle) instance;
        ICE_LOG(LOG_SEV_DEBUG, 
            "stun transaction instance created. Maximum configured "\
            "concurrent transactions: %d", max_txns);
    }

    return status;
}


int32_t stun_txn_instance_set_callbacks(handle h_inst, 
                                        stun_txn_instance_callbacks_t *cbs)
{
    stun_txn_instance_t *instance;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (stun_txn_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;

    return STUN_OK;
}


int32_t stun_txn_destroy_instance(handle h_inst)
{
    stun_txn_instance_t *instance;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (stun_txn_instance_t *) h_inst;

    stun_txn_destroy_table(instance->h_table);

    stun_free(instance);

    return STUN_OK;
}

int32_t stun_create_txn(handle h_inst, stun_txn_type_t type, 
                            stun_transport_type_t tport, handle *h_txn)
{
    stun_txn_context_t *txn;
    int32_t status;

    if ((h_inst == NULL) || (h_txn == NULL) || (type >= STUN_TXN_TYPE_MAX))
        return STUN_INVALID_PARAMS;

    txn = (stun_txn_context_t *) 
                            stun_calloc (1, sizeof(stun_txn_context_t));
    if (txn == NULL)
        return STUN_MEM_ERROR;

    txn->txn_type = type;
    txn->tport = tport;
    if (txn->txn_type == STUN_CLIENT_TXN)
    	txn->state = STUN_OG_TXN_IDLE;
    else
        txn->state = STUN_IC_TXN_IDLE;
    txn->instance = (stun_txn_instance_t *) h_inst;

    txn->rto_params = (stun_txn_timer_params_t *) 
                        stun_calloc (1, sizeof(stun_txn_timer_params_t));
    if (txn->rto_params == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT_PT1;
    }

    txn->rto_params->h_instance = h_inst;
    txn->rto_params->h_txn = txn;
    txn->rto_params->type = STUN_TXN_RTO_TIMER;

    txn->rm_params = (stun_txn_timer_params_t *) 
                        stun_calloc (1, sizeof(stun_txn_timer_params_t));
    if (txn->rm_params == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT_PT2;
    }

    txn->rm_params->h_instance = h_inst;
    txn->rm_params->h_txn = txn;
    txn->rm_params->type = STUN_TXN_RM_TIMER;

    txn->oall_params = (stun_txn_timer_params_t *) 
                        stun_calloc (1, sizeof(stun_txn_timer_params_t));
    if (txn->oall_params == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT_PT3;
    }

    txn->oall_params->h_instance = h_inst;
    txn->oall_params->h_txn = txn;
    txn->oall_params->type = STUN_TXN_OVERALL_TIMER;

    txn->rc_count = 0;
    txn->last_rto = 0;

    /** do not add it to the transaction table yet */
     
    *h_txn = txn;

    return STUN_OK;

ERROR_EXIT_PT3:
    stun_free(txn->rm_params);
ERROR_EXIT_PT2:
    stun_free(txn->rto_params);
ERROR_EXIT_PT1:
    stun_free(txn);

    return status;
}


int32_t stun_txn_set_app_transport_param(handle h_inst, 
                                            handle h_txn, handle h_param)
{
    stun_txn_context_t *txn;
    stun_txn_instance_t *instance;

    if ((h_inst == NULL) || (h_txn == NULL) || (h_param == NULL))
        return STUN_INVALID_PARAMS;

    txn = (stun_txn_context_t *) h_txn;
    instance = (stun_txn_instance_t *) h_inst;

    txn->app_transport_param = h_param;

    return STUN_OK;
}


int32_t stun_txn_set_app_param(handle h_inst, handle h_txn, handle h_param)
{
    stun_txn_context_t *txn_ctxt;
    stun_txn_instance_t *instance;

    if ((h_inst == NULL) || (h_txn == NULL)) 
        return STUN_INVALID_PARAMS;

    txn_ctxt = (stun_txn_context_t *) h_txn;
    instance = (stun_txn_instance_t *) h_inst;

    txn_ctxt->app_param = h_param;

    return STUN_OK;
}


int32_t stun_txn_get_app_param(handle h_inst, handle h_txn, handle *h_param)
{
    stun_txn_context_t *txn_ctxt;
    stun_txn_instance_t *instance;

    if ((h_inst == NULL) || (h_txn == NULL) || (h_param == NULL))
        return STUN_INVALID_PARAMS;

    txn_ctxt = (stun_txn_context_t *) h_txn;
    instance = (stun_txn_instance_t *) h_inst;

    *h_param = txn_ctxt->app_param;

    return STUN_OK;
}


int32_t stun_destroy_txn(handle h_inst, 
                        handle h_txn, bool_t keep_req, bool_t keep_resp)
{
    stun_txn_context_t *txn_ctxt;
    stun_txn_instance_t *instance;
    int32_t status = STUN_OK;

    if ((h_inst == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    txn_ctxt = (stun_txn_context_t *) h_txn;
    instance = (stun_txn_instance_t *) h_inst;

    /** stop any runnnig timers */
    if (txn_ctxt->h_rto_timer)
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rto_timer);

    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Unable to stop RTO timer, will be taken care of "\
                "when the timer is handled");
    }
    else
    {
        stun_free(txn_ctxt->rto_params);
    }
    txn_ctxt->h_rto_timer = NULL;

    status = STUN_OK;
    if (txn_ctxt->h_rm_timer)
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rm_timer);

    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Unable to stop RM timer, will be taken care of "\
                "when the timer is handled");
    }
    else
    {
        stun_free(txn_ctxt->rm_params);
    }
    txn_ctxt->h_rm_timer = NULL;


    status = STUN_OK;
    if (txn_ctxt->h_overall_timer)
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_overall_timer);

    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "Unable to stop RM timer, will be taken care of "\
                "when the timer is handled");
    }
    else
    {
        stun_free(txn_ctxt->oall_params);
    }
    txn_ctxt->h_overall_timer = NULL;


    stun_txn_table_remove_txn(instance->h_table, h_txn);

    /** delete the stun req and response message */
    if (keep_req == false)
        stun_msg_destroy(txn_ctxt->h_req);

    if (keep_resp == false)
        stun_msg_destroy(txn_ctxt->h_resp);

    stun_free(txn_ctxt);

    ICE_LOG(LOG_SEV_DEBUG, "Destroyed transaction with handle %p", h_txn);

    return STUN_OK;
}


int32_t stun_txn_send_stun_message(handle h_inst, handle h_txn, handle h_msg)
{
    stun_txn_context_t *txn;
    stun_txn_instance_t *instance;
    stun_msg_type_t msg_class;
    int32_t status;

    if ((h_inst == NULL) || (h_txn == NULL) || (h_msg == NULL))
        return STUN_INVALID_PARAMS;

    txn = (stun_txn_context_t *) h_txn;
    instance = (stun_txn_instance_t *) h_inst;

    status = stun_msg_get_class(h_msg, &msg_class);
    if (status != STUN_OK)
        return status;

    if (msg_class == STUN_REQUEST)
    {
        stun_txn_utils_generate_txn_id(txn->txn_id, STUN_TXN_ID_BYTES);

        stun_txn_table_add_txn(instance->h_table, h_txn);

        /** set in the message */
        stun_msg_set_txn_id(h_msg, txn->txn_id);

        status = stun_txn_fsm_inject_msg(txn, STUN_REQ, h_msg);
    }
    else if (msg_class == STUN_INDICATION)
    {
        u_char txn_id[STUN_TXN_ID_BYTES];

        stun_txn_utils_generate_txn_id(txn_id, STUN_TXN_ID_BYTES);

        stun_msg_set_txn_id(h_msg, txn->txn_id);

        /** send message to remote */
        status = instance->nwk_send_cb(h_msg, txn->app_transport_param);
    }
    else
    {
        handle h_temp;

        /** STUN_SUCCESS_RESP or STUN_ERROR_RESP */
        status = stun_txn_table_find_txn(instance->h_table, h_msg, &h_temp);
        if ((status == STUN_NOT_FOUND) || (h_temp != h_txn))
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "[STUN TXN] Could not find the transaction while "\
                    "sending response");
            return STUN_INVALID_PARAMS;
        }

        status = stun_txn_fsm_inject_msg(txn, STUN_RESP, h_msg);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "stun_txn_send_stun_message() returned %d", status);
        }
    }

    return status;
}


int32_t stun_txn_inject_timer_message(handle h_timerid,
                                        handle h_timer_arg, handle *h_txn)
{
    stun_txn_timer_params_t *timer_params;
    stun_txn_event_t event;
    stun_txn_instance_t *instance;
    int32_t status;

    if ((h_timerid == NULL) || (h_txn == NULL) || (h_timer_arg == NULL))
        return STUN_INVALID_PARAMS;

    timer_params = (stun_txn_timer_params_t *) h_timer_arg;

    switch (timer_params->type)
    {
        case STUN_TXN_RTO_TIMER:
            event = RETRANS_TIMER;
            break;
        case STUN_TXN_RM_TIMER:
            event = RM_TIMER;
            break;
        case STUN_TXN_OVERALL_TIMER:
            event = OVERALL_TIMER;
            break;
        default:
            event = STUN_EVENT_MAX;
            break;
    }

    if (event == STUN_EVENT_MAX)
    {
        stun_free(timer_params);
        return STUN_INVALID_PARAMS;
    }

    instance = (stun_txn_instance_t *) timer_params->h_instance;

    /** make sure we have the transaction */
    status = stun_txn_table_txn_exists(instance->h_table, timer_params->h_txn);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_INFO, 
            "Some stray transaction timer. Ignoring\n");
        stun_free(timer_params);
        return STUN_OK;
    }

    *h_txn = timer_params->h_txn;

    /** inject into fsm */
    return stun_txn_fsm_inject_msg(timer_params->h_txn, event, NULL);
}

int32_t stun_txn_instance_find_transaction(handle h_inst, 
                                                handle h_msg, handle *h_txn)
{
    stun_txn_instance_t *inst;
    handle h_temp;
    int32_t status;

    if ((h_inst == NULL) || (h_msg == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    inst = (stun_txn_instance_t *) h_inst;

    status = stun_txn_table_find_txn(inst->h_table, h_msg, &h_temp);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_INFO, "Transaction not found\n");
    }
    else
    {
        if (h_temp == NULL)
        {
            ICE_LOG(LOG_SEV_CRITICAL, "Possible logic error? h_temo is NULL");
        }

        *h_txn = h_temp;
    }

    return status;
}

int32_t stun_txn_inject_received_msg (handle h_inst, 
                                                handle h_txn, handle h_msg)
{
    stun_txn_instance_t *inst;
    stun_txn_context_t *txn_ctxt;
    stun_msg_type_t msg_class;
    int32_t status;
    handle h_temp;

    if ((h_inst == NULL) || (h_msg == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    inst = (stun_txn_instance_t *) h_inst;
    txn_ctxt = (stun_txn_context_t *) h_txn;

    status = stun_msg_get_class(h_msg, &msg_class);
    if (status != STUN_OK)
        return status;

    /** make sure given transaction is still alive */
    status = stun_txn_table_find_txn(inst->h_table, h_msg, &h_temp);

    if (msg_class ==  STUN_REQUEST)
    {
        /** hmm... a farm fresh juicy server transaction */ 
    	stun_msg_get_txn_id(h_msg, txn_ctxt->txn_id);

        /** add it the table */
        stun_txn_table_add_txn(inst->h_table, h_txn);

        ICE_LOG (LOG_SEV_DEBUG, 
                "[STUN TXN] incoming STUN request - added transaction "\
                "%p to table", h_txn);

        status = stun_txn_fsm_inject_msg(txn_ctxt, STUN_REQ, h_msg);
    }
    else if (msg_class == STUN_INDICATION)
    {
        /** just drop it */
        status = STUN_TERMINATED;
    }
    else
    {
		/** transaction not found */
        if (status != STUN_OK) return STUN_INVALID_PARAMS;

        /** just to clear doubt, if any */
        if (h_temp != txn_ctxt)
        { 
            ICE_LOG (LOG_SEV_WARNING, 
                    "[STUN TXN] Transaction found but no match!");
            return STUN_INT_ERROR;
        }

        status = stun_txn_fsm_inject_msg(txn_ctxt, STUN_RESP, h_msg);
    }

    return status;
}


int32_t stun_txn_timer_set_handle(handle h_timer, handle timer_handle)
{
    stun_txn_timer_params_t *timer;

    if (h_timer == NULL)
        return STUN_INVALID_PARAMS;

    timer = (stun_txn_timer_params_t *) h_timer;

    if (!timer->timer_handle)
        return STUN_INVALID_PARAMS;

    timer->timer_handle = timer_handle;

    return STUN_OK;
}


int32_t stun_txn_timer_get_handle(handle h_timer, handle *timer_handle)
{
    stun_txn_timer_params_t *timer;

    if (h_timer == NULL)
        return STUN_INVALID_PARAMS;

    timer = (stun_txn_timer_params_t *) h_timer;

    if (!timer->timer_handle)
        return STUN_INVALID_PARAMS;

    *timer_handle = timer->timer_handle;

    return STUN_OK;
}


int32_t stun_txn_timer_get_txn_handle(handle h_timer, 
                                            handle *h_txn, handle *h_txn_inst)
{
    stun_txn_timer_params_t *timer;

    if (h_timer == NULL)
        return STUN_INVALID_PARAMS;

    timer = (stun_txn_timer_params_t *) h_timer;

    *h_txn = timer->h_txn;
    *h_txn_inst = timer->h_instance;

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
