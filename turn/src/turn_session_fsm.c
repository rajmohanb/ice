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
        turn_allocation_timeout,
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
        turn_refresh_resp,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_init_dealloc,
        turn_refresh_allocation,
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
        turn_ignore_msg,
        turn_init_dealloc,
        turn_refresh_allocation,
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
        turn_ignore_msg,
        turn_init_dealloc,
        turn_refresh_allocation,
    },
    /** TURN_OG_DEALLOCATING */
    {
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_ignore_msg,
        turn_dealloc_resp,
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

        if ((error_code == 401) || (error_code == 438))
        {
            handle h_sendmsg;

            /** cache the authentication parameters for subsequent requests */
            status = turn_utils_cache_auth_params(session, h_rcvdmsg);
            if (status != STUN_OK) goto ERROR_EXIT_PT1;

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
            session->h_resp = NULL;
        }
        else 
        {
            session->state = TURN_OG_FAILED;
            session->h_txn = session->h_req = session->h_resp = NULL;
        }
    }
    else
    {
        status = turn_utils_extract_data_from_alloc_resp(session, h_rcvdmsg);

        if (status == STUN_OK)
        {
            if (session->lifetime == 0)
            {
                session->state = TURN_OG_FAILED;
            }
            else
            {
                session->state = TURN_OG_ALLOCATED;

                /** start allocation refresh timer */
                status = turn_utils_start_alloc_refresh_timer(session, 60000);
                if (status != STUN_OK)
                {
                    ICE_LOG (LOG_SEV_ERROR, 
                            "Starting of TURN alloc refresh timer failed %d",
                            status);
                    session->state = TURN_OG_FAILED;
                }
            }
        }

        session->h_txn = session->h_req = session->h_resp = NULL;
    }

    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;

ERROR_EXIT_PT2:
    stun_destroy_txn(h_txn_inst, h_new_txn, false, false);
ERROR_EXIT_PT1:
    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;
}



int32_t turn_allocation_timeout (turn_session_t *session, handle h_msg)
{
    ICE_LOG (LOG_SEV_ERROR, "TURN transaction timed out");

    /** 
     * no timers would have been started at 
     * this stage, so no need to stop any timers 
     */

    /** destroy the transaction */

    session->state = TURN_OG_FAILED;

    return STUN_TERMINATED;
}



int32_t send_perm_req (turn_session_t *session, handle h_msg)
{
    return STUN_OK;
}



int32_t process_perm_resp (turn_session_t *session, handle h_msg)
{
    return STUN_TERMINATED;
}


int32_t turn_init_dealloc (turn_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_txn, h_txn_inst;
    
    h_txn_inst = session->instance->h_txn_inst;

    /** delete an existing transaction, if any */
    stun_destroy_txn(h_txn_inst, session->h_txn, false, false);

    status = turn_utils_create_dealloc_req_msg(session, &session->h_req);
    if (status != STUN_OK)
        return status;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;


    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_req);
    if (status != STUN_OK) return status;

    session->h_txn = h_txn;
    session->state = TURN_OG_DEALLOCATING;

    return status;
}



int32_t turn_refresh_resp (turn_session_t *session, handle h_rcvdmsg)
{
    int32_t status;
    stun_msg_type_t class_type;
    handle h_txn, h_new_txn, h_txn_inst = session->instance->h_txn_inst;
    bool_t txn_terminated = false;

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

        if (error_code == 438)
        {
            handle h_sendmsg;

            /** cache the authentication parameters for subsequent requests */
            status = turn_utils_cache_auth_params(session, h_rcvdmsg);
            if (status != STUN_OK) goto ERROR_EXIT_PT1;

            status = turn_utils_create_refresh_req_msg(session, &h_sendmsg);
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
            session->h_resp = NULL;
        }
        else 
        {
            /** to be handled */
            session->state = TURN_OG_FAILED;
            session->h_txn = session->h_req = session->h_resp = NULL;
        }
    }
    else
    {
        status = turn_utils_extract_data_from_refresh_resp(session, h_rcvdmsg);

        if (status == STUN_OK)
        {
            if (session->lifetime == 0)
            {
                session->state = TURN_OG_FAILED; /** TODO */
            
                ICE_LOG (LOG_SEV_ERROR, "TURN session de-allocated");
            }
            else
            {
                /** (re)start allocation refresh timer */
                status = turn_utils_start_alloc_refresh_timer(session, 60000);
                if (status != STUN_OK)
                {
                    ICE_LOG (LOG_SEV_ERROR, 
                            "Starting of TURN alloc refresh timer failed %d",
                            status);
                    session->state = TURN_OG_FAILED;
                }
            }
        }

        session->h_txn = session->h_req = session->h_resp = NULL;
    }

    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;

ERROR_EXIT_PT2:
    stun_destroy_txn(h_txn_inst, h_new_txn, false, false);
ERROR_EXIT_PT1:
    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;
}




int32_t turn_dealloc_resp (turn_session_t *session, handle h_rcvdmsg)
{
    int32_t status;
    stun_msg_type_t class_type;
    handle h_txn, h_new_txn, h_txn_inst = session->instance->h_txn_inst;
    bool_t txn_terminated = false;

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

        if (error_code == 438)
        {
            handle h_sendmsg;

            /** cache the authentication parameters for subsequent requests */
            status = turn_utils_cache_auth_params(session, h_rcvdmsg);
            if (status != STUN_OK) goto ERROR_EXIT_PT1;

            status = turn_utils_create_refresh_req_msg(session, &h_sendmsg);
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
            session->h_resp = NULL;
        }
        else 
        {
            /** to be handled */
            session->state = TURN_OG_FAILED;
            session->h_txn = session->h_req = session->h_resp = NULL;
        }
    }
    else
    {
        status = turn_utils_extract_data_from_refresh_resp(session, h_rcvdmsg);

        if (status == STUN_OK)
        {
            if (session->lifetime == 0)
            {
                session->state = TURN_OG_FAILED; /** TODO */
            
                ICE_LOG (LOG_SEV_ERROR, "TURN session de-allocated");
            }
        }

        session->h_txn = session->h_req = session->h_resp = NULL;
    }

    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;

ERROR_EXIT_PT2:
    stun_destroy_txn(h_txn_inst, h_new_txn, false, false);
ERROR_EXIT_PT1:
    if (txn_terminated == true)
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

    return status;
}



int32_t turn_refresh_allocation (turn_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_txn, h_txn_inst;
    
    h_txn_inst = session->instance->h_txn_inst;

    /** TODO = session should be capable of supporting multiple concurrent transactions and so has to store multiple txn handles */
    /** delete an existing transaction, if any */
    stun_destroy_txn(h_txn_inst, session->h_txn, false, false);

    status = turn_utils_create_refresh_req_msg(session, &session->h_req);
    if (status != STUN_OK)
        return status;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;


    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_req);
    if (status != STUN_OK) return status;

    session->h_txn = h_txn;

    /** no change in state */

    return status;
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
        ICE_LOG(LOG_SEV_ERROR, 
                "TURN session %p moved to state %d from %d", 
                session, session->state, cur_state);
        status = turn_session_utils_notify_state_change_event(session);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
