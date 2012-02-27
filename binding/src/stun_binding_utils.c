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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_txn_api.h"
#include "stun_binding_api.h"
#include "stun_binding_int.h"
#include "stun_binding_utils.h"


int32_t stun_binding_utils_create_msg(stun_msg_type_t msg_type, handle *h_req)
{
    handle h_msg;
    int32_t status;

    status = stun_msg_create(msg_type, STUN_METHOD_BINDING, &h_msg);
    if (status != STUN_OK) return status;

    *h_req = h_msg;

    return status;
}


int32_t stun_binding_utils_start_refresh_timer(stun_binding_session_t *session)
{
    int32_t status;
    stun_bind_timer_params_t *timer = NULL;

    if(session->refresh_timer == NULL)
    {
        session->refresh_timer = (stun_bind_timer_params_t *) 
                            stun_calloc (1, sizeof(stun_bind_timer_params_t));
        if (session->refresh_timer == NULL)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "[STUN BIND] Memory allocation failed for STUN Binding "\
                    "refresh timer");
            return STUN_NO_RESOURCE;
        }
    }

    timer = session->refresh_timer;
    timer->timer_id = 0;

    timer->h_instance = (handle)session->instance;
    timer->h_bind_session = (handle)session;
    timer->arg = (handle) NULL;
    timer->type = BIND_REFRESH_TIMER;

    timer->timer_id = session->instance->start_timer_cb(
                    session->refresh_duration, session->refresh_timer);
    if (timer->timer_id)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[STUN BINDING] Started STUN Binding refresh timer for %d "\
                "msec ", session->refresh_duration);
        status =  STUN_OK;
    }
    else
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "[STUN BINDING] Starting of STUN Binding refresh timer "\
                "for %d msec failed ", session->refresh_duration);
        status = STUN_INT_ERROR;
    }

    return status;
}


int32_t stun_binding_utils_initiate_session_refresh(
                                        stun_binding_session_t *session)
{
    int32_t status;
    handle h_req;

    /** destroy earlier refresh transaction, if alive */
    if (session->h_txn)
    {
        stun_destroy_txn(session->instance->h_txn_inst, 
                                    session->h_txn, false, false);
        session->h_txn = NULL;
    }

    /** send message */
    status = stun_binding_utils_create_msg(STUN_REQUEST, &h_req);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Error while creating the stun binding message");
        return status;
    }

    status = stun_create_txn(session->instance->h_txn_inst, 
            STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &(session->h_txn));
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(session->instance->h_txn_inst, 
                                        session->h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_transport_param(
                session->instance->h_txn_inst, session->h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(
            session->instance->h_txn_inst, session->h_txn, h_req);
    if (status != STUN_OK) return status;

    /** start refresh timer */
    status = stun_binding_utils_start_refresh_timer(session);

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
