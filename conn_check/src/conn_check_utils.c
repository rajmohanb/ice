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



int32_t cc_utils_create_request_msg(
                            conn_check_session_t *session, handle *h_req)
{
    handle h_msg, ah_attr[MAX_STUN_ATTRIBUTES] = {0};
    int32_t status, i, attr_count = 0;

    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_BINDING, &h_msg);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Creating BINDING req message failed", status);
        return status;
    }

    /** software attribute */
    if (session->instance->client_name)
    {
        status = stun_attr_create(STUN_ATTR_SOFTWARE, &(ah_attr[attr_count]));
        if (status != STUN_OK) goto ERROR_EXIT_PT;
        attr_count++;

        status = stun_attr_software_set_value(ah_attr[attr_count - 1], 
                                            session->instance->client_name, 
                                            session->instance->client_name_len);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    /** use candidate */
    if (session->nominated == true)
    {
        status = stun_attr_create(STUN_ATTR_USE_CANDIDATE, 
                                                    &(ah_attr[attr_count]));
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Creation of use candidate attribute failed");
            goto ERROR_EXIT_PT;
        }
        attr_count++;
    }

    /** priority */
    status = stun_attr_create(STUN_ATTR_PRIORITY, &(ah_attr[attr_count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "[CONN CHECK] Creation of PRIORITY attribute failed");
        goto ERROR_EXIT_PT;
    }
    attr_count++;

    status = stun_attr_priority_set_priority(
                        ah_attr[attr_count - 1], session->prflx_cand_priority);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    /** message integrity */
    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                    &(ah_attr[attr_count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "[CONN CHECK] Creation of MESSAGE-INTEGRITY attribute failed");
        goto ERROR_EXIT_PT;
    }
    attr_count++;

    /** fingerprint */
    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "[CONN CHECK] Creation of FINGERPRINT attribute failed");
        goto ERROR_EXIT_PT;
    }
    attr_count++;

    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "[CONN CHECK] Adding of attributes to BINDING request msg failed");
        goto ERROR_EXIT_PT;
    }

    *h_req = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}

int32_t cc_utils_create_indication(handle *h_msg)
{
    return STUN_OK;
}

int32_t cc_utils_create_response_msg(handle *h_inst)
{
    return STUN_OK;
}


int32_t cc_utils_create_resp_from_req(conn_check_session_t *session,
                     handle h_req, stun_msg_type_t msg_type, handle *h_resp)
{
    int32_t status;
    uint32_t num;
    u_char software[MAX_STR_LEN];
    handle h_msg, h_req_attr[1], h_resp_attr[1];
    stun_addr_family_type_t addr_family;

    h_msg = NULL;
    status = stun_msg_create_resp_from_req(h_req, msg_type, &h_msg);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the response message from request msg failed");
        return status;
    }

    /** make a copy of the software attribute if present */
    num = 1;
    status = stun_msg_get_specified_attributes(h_req, 
                                STUN_ATTR_SOFTWARE, h_req_attr, &num);
    if ((status == STUN_OK) && num)
    {
        uint16_t len = MAX_STR_LEN;
        status = stun_attr_software_get_value(h_req_attr[0], software, &len);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Getting the software value failed");
            goto ERROR_EXIT_PT1;
        }

        status = stun_attr_create(STUN_ATTR_SOFTWARE, &(h_resp_attr[0]));
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Creating the software attribute failed");
            goto ERROR_EXIT_PT1;
        }

        status = stun_attr_software_set_value(h_resp_attr[0], software, len);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "setting the software value failed");
            goto ERROR_EXIT_PT2;
        }

        status = stun_msg_add_attribute(h_msg, h_resp_attr[0]);
        if (status != STUN_OK)
        { 
            ICE_LOG(LOG_SEV_ERROR, 
                "Adding of software attribute to response message failed");
            goto ERROR_EXIT_PT2;
        }

        ICE_LOG(LOG_SEV_DEBUG, "Added software attribute to response msg");
    }

    /* ================================================================== */

    status = stun_attr_create(
                    STUN_ATTR_XOR_MAPPED_ADDR, &(h_resp_attr[0]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the xor_mapped_addr attribute failed");
        goto ERROR_EXIT_PT1;
    }

    if (session->stun_server_type == STUN_INET_ADDR_IPV4) {
        addr_family = STUN_ADDR_FAMILY_IPV4;
    } else if (session->stun_server_type == STUN_INET_ADDR_IPV6) {
        addr_family = STUN_ADDR_FAMILY_IPV6;
    }

    status = stun_attr_xor_mapped_addr_set_address(
                                    h_resp_attr[0], session->stun_server, 
                                    strlen((char *)session->stun_server),
                                    addr_family);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Setting of the xor mapped addr to xor_mapped_addr "\
            "attribute failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_attr_xor_mapped_addr_set_port(
                                    h_resp_attr[0], session->stun_port);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Setting of the xor mapped port to xor_mapped_addr "\
            "attribute failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_msg_add_attribute(h_msg, h_resp_attr[0]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of xor mapped addr attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    /* ================================================================== */

    status = stun_attr_create(
                    STUN_ATTR_MESSAGE_INTEGRITY, &(h_resp_attr[0]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the message intergrity attribute failed");
        goto ERROR_EXIT_PT1;
    }

    status = stun_msg_add_attribute(h_msg, h_resp_attr[0]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of message integrity attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    /* ================================================================== */

    status = stun_attr_create(
                    STUN_ATTR_FINGERPRINT, &(h_resp_attr[0]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the fingerprint attribute failed");
        goto ERROR_EXIT_PT1;
    }

    status = stun_msg_add_attribute(h_msg, h_resp_attr[0]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of fingerprint attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    /* ================================================================== */

    *h_resp = h_msg;

    return STUN_OK;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_resp_attr[0]);
ERROR_EXIT_PT1:
    stun_msg_destroy(h_msg);

    return status;
}


int32_t cc_utils_extract_data_from_binding_resp(
                                conn_check_session_t *session, handle h_msg)
{
#if 0
    handle h_attr[0];
    int32_t num, len, status;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_MAPPED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_mapped_addr_get_address(
                                    h_attr[0], session->srflx_ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_mapped_addr_get_port(
                                    h_attr[0], &session->srflx_port);
    if (status != STUN_OK) return status;


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_RELAYED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_relayed_addr_get_address(
                                    h_attr[0], session->relay_ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_relayed_addr_get_port(
                                    h_attr[0], &session->relay_port);
    if (status != STUN_OK) return status;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_lifetime_get_duration(
                                    h_attr[0], &session->lifetime);
    if (status != STUN_OK) return status;
#endif
    int32_t status = STUN_OK;
    return status;
}


int32_t cc_utils_get_app_data_for_current_state(
                                conn_check_session_t *session, handle *data)
{
    conn_check_result_t *result = NULL;

    switch(session->state)
    {
        case CC_OG_IDLE:
        case CC_OG_CHECKING:
        case CC_OG_INPROGRESS:
            break;

        case CC_OG_TERMINATED:
        {
            result = (conn_check_result_t *)
                        stun_calloc(1, sizeof(conn_check_result_t));
            if (result == NULL) return STUN_MEM_ERROR;

            result->cc_succeeded = session->cc_succeeded;

            /** TODO - copy peer reflexive address if learned */
        }
        break;

        case CC_IC_TERMINATED:
        {
            result = (conn_check_result_t *)
                        stun_calloc(1, sizeof(conn_check_result_t));
            if (result == NULL) return STUN_MEM_ERROR;

            result->cc_succeeded = session->cc_succeeded;
            result->nominated = session->nominated;
        }
        break;

        case CC_IC_IDLE:
            break;

        default:
            break;
    }

    *data = result;
    return STUN_OK;
}


int32_t conn_check_utils_verify_request_msg(
                    conn_check_session_t *session, handle h_msg)
{
    int32_t status;
    uint32_t num, local_len, peer_len;
    handle h_username_attr, h_fingerprint_attr, h_msg_int_attr, h_unknown;
    u_char *username = NULL;
    u_char *localuser, *peeruser;

    /** fingerprint is a MUST in the request */
    num = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_FINGERPRINT, &h_fingerprint_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "FingerPrint attribute missing. Message validation failed");
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Extracting FingerPrint attribute from the message failed");
        return status;
    }


    ICE_LOG(LOG_SEV_INFO, 
            "FINGERPRINT attribute is present in the received message");

    status = stun_msg_validate_fingerprint(h_msg);
    if (status == STUN_VALIDATON_FAIL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Fingerprint validation failed. Sending 400 Bad Request");
        conn_check_utils_send_error_resp(session, 
                                        400, STUN_REJECT_RESPONSE_400);
        return STUN_VALIDATON_FAIL;
    }

    ICE_LOG(LOG_SEV_INFO, "FINGERPRINT CRC is valid for the message");

    /** checks pertaining to short term authentication start here */

    /*
     * rfc5389 sec 10.1.2 Receiving a request or indication
     *
     * If the message does not contain both a MESSAGE-INTEGRITY and USERNAME
     * attribute:
     * - If the message is a request, the server must reject the request with
     *   an error response. This response must use an error code of i
     *   400 (Bad Request)
     */
    num = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_MESSAGE_INTEGRITY, &h_msg_int_attr, &num);
    if (status == STUN_NOT_FOUND)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
                "Message Integrity attribute missing. Message validation "\
                "failed. Sending 400 Bad Request");
        conn_check_utils_send_error_resp(session, 
                                        400, STUN_REJECT_RESPONSE_400);
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Extracting Message Integrity attribute from the message failed");
        return status;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "MESSAGE-INTEGRITY attribute is present in the received message");

    /** check for username attribute */
    num = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_USERNAME, &h_username_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Username attribute missing. Message validation "\
                "failed. Sending 400 Bad Request");
        conn_check_utils_send_error_resp(session, 
                                        400, STUN_REJECT_RESPONSE_400);
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Extracting Username attribute from the message failed");
        return status;
    }


    ICE_LOG(LOG_SEV_INFO, 
            "USERNAME attribute is present in the received message");

    /*
     * rfc5389 sec 10.1.2 Receiving a request or indication
     *
     * If the USERNAME does not contain a username value currently valid
     * within the server:
     * - If the message is a request, the server must reject the request with
     *   an error response. This response must use an error code of i
     *   401 (Unauthorized)
     */
    status = stun_attr_username_get_username_length(h_username_attr, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Extracting username length from USERNAME attribute failed");
        return STUN_VALIDATON_FAIL;
    }

    username = (u_char *) stun_calloc(1, num);
    if (username == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Memory allocation failed while extracting username value");
        return STUN_MEM_ERROR;
    }

    status = stun_attr_username_get_username(h_username_attr, username, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Extracting username value from USERNAME attribute failed");
        status = STUN_VALIDATON_FAIL;
        goto ERROR_EXIT_PT;
    }

    status = conn_check_utils_extract_username_components(
                username, num, &localuser, &local_len, &peeruser, &peer_len);
    if ((status != STUN_OK) || (local_len == 0) || (peer_len == 0))
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "username value validation failed. Sending 400 Bad Request");
        conn_check_utils_send_error_resp(session, 
                                        400, STUN_REJECT_RESPONSE_400);
        status = STUN_VALIDATON_FAIL;
        goto ERROR_EXIT_PT;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "Local username value %s and %d length", localuser, local_len);
    ICE_LOG(LOG_SEV_INFO, 
            "Peer username value %s and %d length", peeruser, peer_len);
    
    /** check if the username is valid for this session */
    if ((local_len != session->local_user_len) ||
        (stun_strncmp((char *)session->local_user, 
                                    (char *)localuser, local_len) != 0))
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Invalid username value for this session. Sending "\
                "401 Unauthorized");
        conn_check_utils_send_error_resp(session, 
                                        401, STUN_REJECT_RESPONSE_401);

        status = STUN_VALIDATON_FAIL;
        goto ERROR_EXIT_PT;
    }

    ICE_LOG(LOG_SEV_INFO, "username is valid for this session");
    stun_free(username);

    /*
     * rfc5389 sec 10.1.2 Receiving a request or indication
     *
     * Using the password associated with the username, compute the value
     * for the message integrity as described in section 15.4. if the resulting
     * value does not match the contents of the MESSAGE-INTEGRITY attribute:
     * - If the message is a request, the server MUST reject the request with
     *   an error response. This response MUST use an error code of 
     *   401 (Unauthorized)
     */
    status = stun_msg_validate_message_integrity(
                        h_msg, session->local_pwd, session->local_pwd_len);
    if (status == STUN_VALIDATON_FAIL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Message Integrity validation failed. Sending 401 Unauthorized");
        conn_check_utils_send_error_resp(session, 
                                        401, STUN_REJECT_RESPONSE_401);
        return STUN_VALIDATON_FAIL;
    }

    /** checks pertaining to short term authentication end */

    /** 
     * rfc 5389 sec 7.3 Receiving a STUN Message
     * Unknown comprehension-optional attributes MUST be ignored by the agent
     */

    /** 
     * rfc 5389 sec 7.3.1 Processing a Request
     * If the request contains one or more unknown comprehension-required
     * attributes, the server replies with an error response with an error
     * code of 420 (Unknown Attribute), and includes an UNKNOWN-ATTRIBUTES
     * attribute in the response that lists the unknown comprehension-
     * required attributes.
     */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                    STUN_ATTR_UNKNOWN_COMP_REQUIRED, &h_unknown, &num);
    if ((status == STUN_OK) && (num > 0))
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "%d Unknown comprehension required attributes are present "\
                "in the message. Hence sending 420 error response", num);

        conn_check_utils_send_error_resp(session,
                                        420, STUN_REJECT_RESPONSE_420);
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Extracting unknown comprehension required attributes "\
                "from the message failed");

        return status;
    }


    return STUN_OK;

ERROR_EXIT_PT:

    if (username) stun_free(username);
    return status;
}


int32_t conn_check_utils_extract_info_from_request_msg(
            conn_check_session_t *session, handle h_msg)
{
    handle h_attrs[10];
    uint32_t num;
    int32_t status;

    num = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_USE_CANDIDATE, h_attrs, &num);
    if (status == STUN_OK)
    {
        session->nominated = true;
    }
    else if (status == STUN_NOT_FOUND)
    {
        session->nominated = false;
        status = STUN_OK;
    }

    return status;
}


int32_t conn_check_utils_send_error_resp(
        conn_check_session_t *session, uint32_t error_code, char *reason)
{
    int32_t status;
    handle h_error_code;
    handle h_txn_inst = session->instance->h_txn_inst;

    status = stun_msg_create_resp_from_req(
                        session->h_req, STUN_ERROR_RESP, &(session->h_resp));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the response message from request msg failed");
        return status;
    }

    /** now add error code attribute */
    status = stun_attr_create(STUN_ATTR_ERROR_CODE, &h_error_code);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the error-code attribute failed");
        goto ERROR_EXIT_PT1;
    }

    status = stun_attr_error_code_set_error_code(h_error_code, error_code);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code attribute value failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_attr_error_code_set_error_reason(
                                    h_error_code, reason, strlen(reason));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code reason value failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_msg_add_attribute(session->h_resp, h_error_code);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of error code attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Added error code attribute to response msg");

    if (error_code == 420)
    {
        handle h_unknown_attr[5];
        uint32_t num = 5;

        status = stun_msg_get_specified_attributes(session->h_req, 
                        STUN_ATTR_UNKNOWN_COMP_REQUIRED, h_unknown_attr, &num);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Adding of error code attribute to response message failed");
            goto ERROR_EXIT_PT1;
        }

        status = stun_msg_utils_add_unknown_attributes(
                                        session->h_resp, h_unknown_attr, num);
    }

    /** send the message to perr */
    status = stun_txn_send_stun_message(
                        h_txn_inst, session->h_txn, session->h_resp);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, "Sending of STUN message failed");
        goto ERROR_EXIT_PT1;
    }

    session->state = CC_IC_TERMINATED;
    session->cc_succeeded = false;

    return STUN_OK;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_error_code);
ERROR_EXIT_PT1:
    stun_msg_destroy(session->h_resp);

    return status;
}


int32_t conn_check_utils_extract_username_components(
                u_char *username, uint32_t len, u_char **local_user, 
                uint32_t *local_len, u_char **peer_user, uint32_t *peer_len)
{
    uint32_t i;

    if ((username == NULL) || (len == 0))
        return STUN_VALIDATON_FAIL; 

    *local_user = username;

    for (i = 0; i < len; i++)
    {
        if (*username == ':')
        {
            *local_len = i;
            *peer_user = ++username;
            *peer_len = len - i - 1;
            break;
        }
        username++;
    }

    if (*local_len == 0)
        *local_user = NULL;

    if (*peer_len == 0)
        *peer_user = NULL;

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
