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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_txn_api.h"
#include "conn_check_api.h"
#include "conn_check_int.h"
#include "conn_check_utils.h"
#include "conn_check_session_fsm.h"



static conn_check_session_fsm_handler 
    conn_check_session_fsm[CC_STATE_MAX][CONN_CHECK_EVENT_MAX] =
{
    /** CC_OG_IDLE */
    {
        cc_initiate,
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_OG_CHECKING */
    {
        cc_ignore_event,
        cc_handle_resp,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_OG_TERMINATED */
    {
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_IC_IDLE */
    {
        cc_process_ic_check,
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_IC_TERMINATED */
    {
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
    }
};


int32_t cc_initiate (conn_check_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_txn, h_txn_inst;

    status = cc_utils_create_request_msg(session, &session->h_req);
    if (status != STUN_OK)
        return status;

    h_txn_inst = session->instance->h_txn_inst;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_transport_param(h_txn_inst, 
                                                    h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_req);
    if (status != STUN_OK) return status;

    session->h_txn = h_txn;
    session->state = CC_OG_CHECKING;

    return status;
}



int32_t cc_process_ic_check (conn_check_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_resp, h_txn, h_txn_inst;

    h_txn_inst = session->instance->h_txn_inst;

    status = stun_create_txn(h_txn_inst,
                    STUN_SERVER_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_inject_received_msg(h_txn_inst, h_txn, h_msg);
    if (status != STUN_OK) return status;

    session->h_req = h_msg;
    session->h_txn = h_txn;

#ifdef ICE_STUN_REQ_VALIDATION
    /** 
     * make sure the received request message has the USERNAME
     * and MESSAGE-INTEGRITY attributes. These are a must for the conn
     * check binding request message.
     */
    status = conn_check_utils_verify_request_msg(session, h_msg);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Incmoing conn check request message "\
                "validation failed");
        return STUN_TERMINATED;
    }
#endif

    status = conn_check_utils_extract_info_from_request_msg(session, h_msg);
    if (status != STUN_OK)
    {
        return STUN_TERMINATED;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "[CONN CHECK] Incoming conn check request validation succeeded. "\
            "All decks clear for sending response");

    /** if everything is fine, then go ahead and send success response */
    status = cc_utils_create_resp_from_req(
                    session, h_msg, STUN_SUCCESS_RESP, &h_resp);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Creating a response from the request "\
                "message failed");
        return status;
    }

    session->h_resp = h_resp;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, h_resp);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Sending conn check response via stun "\
                "transaction failed - %d", status);
        return status;
    }

    session->state = CC_IC_TERMINATED;
    session->cc_succeeded = true;

    return STUN_TERMINATED;
}


int32_t cc_handle_resp (conn_check_session_t *session, handle h_rcvdmsg)
{
    int32_t status;
    handle h_txn, h_txn_inst = session->instance->h_txn_inst;

    status = stun_txn_instance_find_transaction(h_txn_inst, h_rcvdmsg, &h_txn);
    if (status != STUN_OK)
        return status;

    status = stun_txn_inject_received_msg(h_txn_inst, h_txn, h_rcvdmsg);
    if (status == STUN_OK) { }
    else if (status == STUN_TERMINATED)
    {
        stun_destroy_txn(h_txn_inst, h_txn, false, false);
        session->state = CC_OG_TERMINATED;
        session->cc_succeeded = true;
    }

    return status;
}

int32_t cc_ignore_event (conn_check_session_t *session, handle h_msg)
{
    return STUN_OK;
}

int32_t conn_check_session_fsm_inject_msg(
                                    conn_check_session_t *session, 
                                    conn_check_event_t event, handle h_msg)
{
    conn_check_session_fsm_handler handler;

    handler = conn_check_session_fsm[session->state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    return handler(session, h_msg);
}

/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
