/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
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
    },
    /** CC_OG_CHECKING */
    {
        cc_ignore_event,
        cc_handle_resp,
        cc_timeout,
    },
    /** CC_OG_TERMINATED */
    {
        cc_ignore_event,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_IC_IDLE */
    {
        cc_process_ic_check,
        cc_ignore_event,
        cc_ignore_event,
    },
    /** CC_IC_TERMINATED */
    {
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
    if (status != STUN_OK) return status;

    ICE_LOG(LOG_SEV_INFO,
            "<<OG CONN CHECK>> => %s %d", session->stun_server, 
            session->stun_port);

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



int32_t cc_process_ic_check (conn_check_session_t *session, handle h_rcvdmsg)
{
    int32_t status, respcode;
    handle h_resp, h_txn, h_txn_inst, h_msg;
    conn_check_rx_pkt_t *rx_msg = (conn_check_rx_pkt_t *) h_rcvdmsg;

    h_msg = rx_msg->h_msg;
    h_txn_inst = session->instance->h_txn_inst;

    status = stun_create_txn(h_txn_inst,
                    STUN_SERVER_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;

    session->h_txn = h_txn;

    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_inject_received_msg(h_txn_inst, h_txn, h_msg);
    if (status != STUN_OK) return status;

    session->h_req = h_msg;

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

    status = conn_check_utils_extract_info_from_request_msg(session, h_msg);
    if (status != STUN_OK)
    {
        return STUN_TERMINATED;
    }

    /** connectivity check specific verification */
    respcode = 0;
    status = conn_check_detect_repair_role_conflicts(session, h_msg, &respcode);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Error while detecting and repairing role conflict");
        return STUN_TERMINATED;
    }

    if (respcode == STUN_ERROR_ROLE_CONFLICT)
    {
        ICE_LOG(LOG_SEV_WARNING, 
            "Role conflict detected. Sending 487 Role Conflict response");

        conn_check_utils_send_error_resp(session, 
                                        401, STUN_REJECT_RESPONSE_401);
    }
    else
    {
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
    }

    return STUN_TERMINATED;
}


int32_t cc_handle_resp (conn_check_session_t *session, handle h_rcvdmsg)
{
    int32_t status;
    handle h_txn, h_txn_inst = session->instance->h_txn_inst;
    bool_t txn_terminated = false;
    stun_msg_type_t msg_class;
    conn_check_rx_pkt_t *rx_msg = (conn_check_rx_pkt_t *) h_rcvdmsg;

    /** normal processing and validation of a packet as defined in STUN RFC */
    /** sec 10.1.3 of RFC 5389 */
    status = stun_msg_validate_message_integrity(rx_msg->h_msg, 
                                session->peer_pwd, session->peer_pwd_len);
    if (status == STUN_VALIDATON_FAIL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Message Integrity validation failed for received response. "\
            "Hence discarding the message");
        return STUN_VALIDATON_FAIL;
    }


    /**
     * RFC 5245 sec 7.1.2 - Processing the response
     */
    status = stun_txn_instance_find_transaction(h_txn_inst, rx_msg->h_msg, &h_txn);
    if (status != STUN_OK) return status;

    status = stun_txn_inject_received_msg(h_txn_inst, h_txn, rx_msg->h_msg);
    if (status == STUN_OK)
    {
        return status;
    }
    else if (status == STUN_TERMINATED)
    {
        txn_terminated = true;
    }
    else
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] stun txn injection rcvd msg returned error %d", 
                status);
        return status;
    }

    /** 
     * check that the source IP address and port of the response equals the
     * destination IP address and port that the Binding request was sent to.
     * and that the destination IP address and port of the response matches
     * the source IP address and port that the Binding request was sent from.
     */
    if ((rx_msg->src.host_type != session->stun_server_type) || 
        (conn_check_utils_host_compare(rx_msg->src.ip_addr, 
                                       session->stun_server, 
                                       session->stun_server_type) == false) ||
        (rx_msg->src.port != session->stun_port) ||
        (rx_msg->transport_param != session->transport_param))
    {
        /** not symmetric */
        session->cc_succeeded = false;
        status = STUN_TERMINATED;

        goto ERROR_EXIT_PT;
    }

    /** check if success or failure response */
    status = stun_msg_get_class(rx_msg->h_msg, &msg_class);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Unable to extract the STUN msg class %d", status);
        goto ERROR_EXIT_PT;
    }

    if (msg_class == STUN_ERROR_RESP)
    {
        /**
         * if failure, RFC 5245 sec 7.1.2.1 - Failure Cases
         */
        session->cc_succeeded = false;

        /** get STUN error code */
        status = cc_utils_extract_error_code(rx_msg->h_msg, &session->error_code);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }
    else if(msg_class == STUN_SUCCESS_RESP)
    {
        /**
         * if success, RFC 5245 sec 7.1.2 - Success Cases
         */
        session->cc_succeeded = true;

        /** extract the mapped address */
        status = cc_utils_extract_conn_check_info(rx_msg->h_msg, session);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }
    else
        goto ERROR_EXIT_PT;

    if (txn_terminated == true)
    {
        stun_destroy_txn(h_txn_inst, h_txn, false, false);

        session->h_txn = session->h_req = session->h_resp = NULL;
    }

    session->state = CC_OG_TERMINATED;
    return STUN_TERMINATED;

ERROR_EXIT_PT:
    if (txn_terminated == true)
    {
        stun_destroy_txn(h_txn_inst, h_txn, false, false);
        session->h_txn = session->h_req = session->h_resp = NULL;
    }

    session->cc_succeeded = false;

    return status;
}



int32_t cc_timeout (conn_check_session_t *session, handle h_txn)
{
    int32_t status;
    handle h_txn_inst = session->instance->h_txn_inst;

    /** 
     * stun transaction related to this 
     * session has timed out and terminated.
     */
    ICE_LOG(LOG_SEV_ERROR, 
            "[CONN CHECK] stun txn terminated due to timeout");

    status = stun_destroy_txn(h_txn_inst, h_txn, false, false);
    if (status == STUN_OK)
    {
        session->cc_succeeded = false;
        session->h_txn = session->h_req = session->h_resp = NULL;
        session->state = CC_OG_TERMINATED;
    }
    else
    {
        ICE_LOG(LOG_SEV_ERROR,
                "[CONN CHECK] Destroying of STUN transaction failed %d", 
                status);
    }
    
    return STUN_TERMINATED;
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
