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
#include "turn_api.h"
#include "turn_int.h"
#include "turn_utils.h"
#include "turn_session_fsm.h"



static turn_session_fsm_handler 
    turn_session_fsm[TURN_STATE_MAX][TURN_EVENT_MAX] =
{
    /** TURN_IDLE */
    {
        send_alloc_req,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    },
    /** TURN_OG_ALLOCATING */
    {
        turn_ignore_msg,
        process_alloc_resp,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    },
    /** TURN_OG_ALLOCATED */
    {
        turn_ignore_msg,
        turn_ignore_msg,
        send_perm_req,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    },
    /** TURN_OG_CREATING_PERM */
    {
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        process_perm_resp,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    },
    /** TURN_OG_ACTIVE */
    {
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    },
    /** TURN_OG_FAILED */
    {
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
    }
};

int32_t send_alloc_req (turn_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_txn, h_txn_inst;

    status = turn_utils_create_request_msg(
                                STUN_METHOD_ALLOCATE, &session->h_req);
    if (status != STUN_OK)
        return status;

    h_txn_inst = session->instance->h_txn_inst;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;


    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    //status = stun_txn_set_app_transport_param(h_txn_inst, 
    //                                    h_txn, session->transport_param);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_req);
    if (status != STUN_OK) return status;

    session->h_txn = h_txn;
    session->state = TURN_OG_ALLOCATING;

    return status;
}



int32_t process_alloc_resp (turn_session_t *session, handle h_rcvdmsg)
{
    int32_t status;
    stun_msg_type_t class_type;
    handle h_txn, h_new_txn, h_txn_inst = session->instance->h_txn_inst;
    bool_t txn_terminated = false;

    /** 
     * note: 
     * split up the response based on 1xx, 2xx etc to split up this huge handler
     */

    status = stun_txn_instance_find_transaction(h_txn_inst, h_rcvdmsg, &h_txn);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "STUN Transaction not found, ignoring the message");
        return status;
    }

    status = stun_txn_inject_received_msg(h_txn_inst, h_txn, h_rcvdmsg);
    if (status == STUN_TERMINATED)
    { 
        txn_terminated = true; 
    }
    else if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "STUN Transaction returned error %d", status);
        goto ERROR_EXIT_PT1;
    }

    status = stun_msg_get_class(h_rcvdmsg, &class_type);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "Error while extracting message class %d", status);
        goto ERROR_EXIT_PT1;
    }

    if (class_type == STUN_ERROR_RESP)
    {
        uint32_t error_code, num = 1;
        handle h_error_code_attr;

        status = stun_msg_get_specified_attributes(h_rcvdmsg, 
                                STUN_ATTR_ERROR_CODE, &h_error_code_attr, &num);
        if (status != STUN_OK) goto ERROR_EXIT_PT1;

        if (num == 0)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "Error code attribute missing in the received response");
            goto ERROR_EXIT_PT1;
        }

        status = stun_attr_error_code_get_error_code(
                                            h_error_code_attr, &error_code);
        if (status != STUN_OK) goto ERROR_EXIT_PT1;

        if (error_code == 401)
        {
            handle h_sendmsg;

            status = turn_utils_create_alloc_req_msg_with_credential(
                                                        session, &h_sendmsg);
            if (status != STUN_OK) goto ERROR_EXIT_PT1;

            status = stun_create_txn(h_txn_inst, 
                        STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_new_txn);
            if (status != STUN_OK)
            { 
                stun_msg_destroy(h_sendmsg);
                goto ERROR_EXIT_PT1;
            }

            status = stun_txn_set_app_transport_param(h_txn_inst, 
                                                        h_new_txn, session);
            if (status != STUN_OK) goto ERROR_EXIT_PT2;

            status = stun_txn_set_app_param(h_txn_inst, h_new_txn, (handle)session);
            if (status != STUN_OK) goto ERROR_EXIT_PT2;

            status = stun_txn_send_stun_message(h_txn_inst, h_new_txn, h_sendmsg);
            if (status != STUN_OK) goto ERROR_EXIT_PT2;

            session->h_req = h_sendmsg;
            session->h_txn = h_new_txn;
        }
        else 
        {
            /** to be handled */
            session->state = TURN_OG_FAILED;
            return status;
        }
    }
    else
    {
        status = turn_utils_extract_data_from_alloc_resp(session, h_rcvdmsg);

        if (status == STUN_OK)
            session->state = TURN_OG_ALLOCATED;
    }

    return status;

ERROR_EXIT_PT2:
    stun_destroy_txn(h_txn_inst, h_new_txn, false, false);
ERROR_EXIT_PT1:
    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;
}



int32_t send_perm_req (turn_session_t *session, handle h_msg)
{
    return STUN_OK;
}



int32_t process_perm_resp (turn_session_t *session, handle h_msg)
{
    return STUN_TERMINATED;
}



int32_t turn_ignore_msg (turn_session_t *session, handle h_msg)
{
    return STUN_OK;
}



int32_t turn_session_fsm_inject_msg(turn_session_t *session, 
                                    turn_event_t event, handle h_msg)
{
    int32_t status;
    turn_session_state_t cur_state;
    turn_session_fsm_handler handler;

    cur_state = session->state;
    handler = turn_session_fsm[cur_state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(session, h_msg);

    if (cur_state != session->state)
    {
        turn_session_utils_notify_state_change_event(session);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
