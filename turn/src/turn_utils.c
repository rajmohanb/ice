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
#include "turn_api.h"
#include "turn_int.h"


int32_t turn_utils_create_request_msg(turn_session_t *session, 
                                    stun_method_type_t method, handle *h_msg)
{
    int32_t status;
    handle h_req, h_vendor;

    status = stun_msg_create(STUN_REQUEST, method, &h_req);
    if (status != STUN_OK) return status;

    /** software attribute */
    if (session->instance->client_name)
    {
        status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_vendor);
        if (status != STUN_OK) goto ERROR_EXIT_PT1;

        status = stun_attr_software_set_value(h_vendor, 
                                            session->instance->client_name, 
                                            session->instance->client_name_len);
        if (status != STUN_OK) goto ERROR_EXIT_PT2;

        status = stun_msg_add_attribute(h_req, h_vendor);
        if (status != STUN_OK) goto ERROR_EXIT_PT2;
    }

    *h_msg = h_req;
    return status;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_vendor);

ERROR_EXIT_PT1:
    stun_msg_destroy(h_req);

    return status;
}



int32_t turn_utils_create_indication(handle *h_msg)
{
    return STUN_OK;
}



int32_t turn_utils_create_response_msg(handle *h_inst)
{
    return STUN_OK;
}



int32_t turn_utils_cache_auth_params(turn_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_attr;
    uint32_t num, len;

    /** nonce */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_NONCE, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_nonce_get_nonce_length(h_attr, &len);
    if (status != STUN_OK) return status;

    if (len > session->nonce_len)
    {
        stun_free(session->nonce);

        session->nonce = (u_char *) stun_calloc (1, len);
        if (session->nonce == NULL) return STUN_MEM_ERROR;
    }
   
    session->nonce_len = len;

    status = stun_attr_nonce_get_nonce(h_attr, 
                            session->nonce, &(session->nonce_len));
    if (status != STUN_OK) return status;

    /** realm */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_realm_get_realm_length(h_attr, &len);
    if (status != STUN_OK) return status;

    if (len > session->realm_len)
    {
        stun_free(session->realm);

        session->realm = (u_char *) stun_calloc (1, len);
        if (session->realm == NULL) return STUN_MEM_ERROR;
    }
   
    session->realm_len = len;

    status = stun_attr_realm_get_realm(h_attr, 
                            session->realm, &(session->realm_len));
    if (status != STUN_OK) return status;

    return STUN_OK;
}



int32_t turn_utils_create_alloc_req_msg_with_credential(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;

    status = turn_utils_create_request_msg(session, STUN_METHOD_ALLOCATE, &h_msg);
    if (status != STUN_OK) return status;
    
     
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    
    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
                            session->realm, session->realm_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                                ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) return status;

    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



int32_t turn_utils_create_dealloc_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                            STUN_METHOD_REFRESH, &h_msg);
    if (status != STUN_OK) return status;


    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                                session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
                                session->realm, session->realm_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                            ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_LIFETIME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_lifetime_set_duration(ah_attr[attr_count - 1], 0);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                            &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



int32_t turn_utils_extract_data_from_alloc_resp(
                                turn_session_t *session, handle h_msg)
{
    handle h_attr;
    int32_t status;
    uint32_t num, len;
    stun_addr_family_type_t addr_family;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_MAPPED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_mapped_addr_get_address(h_attr, 
                            &addr_family, session->mapped_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_mapped_addr_get_port(
                                    h_attr, &(session->mapped_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only? */
    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        session->mapped_addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        session->mapped_addr.host_type = STUN_INET_ADDR_IPV6;
    else
        session->mapped_addr.host_type = STUN_INET_ADDR_MAX;


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_RELAYED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_relayed_addr_get_address(h_attr, 
                            &addr_family, session->relay_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_relayed_addr_get_port(
                                    h_attr, &(session->relay_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only */
    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        session->relay_addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        session->relay_addr.host_type = STUN_INET_ADDR_IPV6;
    else
        session->relay_addr.host_type = STUN_INET_ADDR_MAX;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status != STUN_OK) return status;

    if (num > 0)
    {
        status = stun_attr_lifetime_get_duration(
                                    h_attr, &session->lifetime);
        if (status != STUN_OK) return status;
    }

    return status;
}



int32_t turn_utils_extract_data_from_refresh_resp(
                                turn_session_t *session, handle h_msg)
{
    handle h_attr;
    int32_t status;
    uint32_t num;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_lifetime_get_duration(
                                h_attr, &session->lifetime);
    return status;
}



int32_t turn_utils_create_refresh_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                            STUN_METHOD_REFRESH, &h_msg);
    if (status != STUN_OK) return status;

    
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
                            session->realm, session->realm_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                            &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                                ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_LIFETIME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    /** put in default refresh duration */
    status = stun_attr_lifetime_set_duration(ah_attr[attr_count - 1], 2000);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}




int32_t turn_session_utils_notify_state_change_event(turn_session_t *session)
{
    int32_t i, status = STUN_OK;
    turn_instance_t *instance = session->instance;

    session->instance->state_change_cb(
                    session->instance, session,  session->state);
   
    /** 
     * once the execution control goes back to the application via callback,
     * the application might destroy the session within the handler function.
     * Hence check for the validity of the session after returning from the
     * app callback handler. But the assumption is that the instance is intact.
     */
    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
        if (instance->ah_session[i] == session) break;

    if (i == TURN_MAX_CONCURRENT_SESSIONS) {
        ICE_LOG(LOG_SEV_ERROR, 
                "Invalid TURN session handle. Probably application destroyed "\
                "the session in the notification handler routine");
        status = STUN_TERMINATED;
    }

    return status;
}



int32_t turn_utils_start_alloc_refresh_timer(
                                turn_session_t *session, uint32_t duration)
{
    turn_timer_params_t *timer;

    if(session->alloc_refresh_timer_params == NULL)
    {
        session->alloc_refresh_timer_params = (turn_timer_params_t *) 
                                stun_calloc (1, sizeof(turn_timer_params_t));

        if (session->alloc_refresh_timer_params == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Memory allocation failed for TURN Allocation refresh timer");
            return STUN_MEM_ERROR;
        }
    }

    timer = session->alloc_refresh_timer_params;

    timer->h_instance = session->instance;
    timer->h_turn_session = session;
    timer->arg = NULL;
    timer->type = TURN_ALLOC_REFRESH_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of timer failed");
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURN session %p allocation "\
            "refresh timer for duration %d seconds timer %p ", 
            session, duration/1000, timer->timer_id);

    return STUN_OK;
}


int32_t turn_utils_create_permission_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    stun_addr_family_type_t addr_family;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                STUN_METHOD_CREATE_PERMISSION, &h_msg);
    if (status != STUN_OK) return status;

    /** Multiple xor XOR-PEER-ADDRESS attributes ca be added */
    for (i = 0; i < TURN_MAX_PERMISSIONS; i++)
    {
        if (session->peer_addr[i].port == 0) break;

        status = stun_attr_create(STUN_ATTR_XOR_PEER_ADDR, 
                                                &(ah_attr[attr_count]));
        if (status != STUN_OK) goto ERROR_EXIT_PT;
        attr_count++;

        if (session->peer_addr[i].host_type == STUN_INET_ADDR_IPV4)
            addr_family = STUN_ADDR_FAMILY_IPV4;
        else if (session->peer_addr[i].host_type == STUN_INET_ADDR_IPV6)
            addr_family = STUN_ADDR_FAMILY_IPV6;
        else
            goto ERROR_EXIT_PT;


        status = stun_attr_xor_peer_addr_set_address(
                ah_attr[attr_count - 1], session->peer_addr[i].ip_addr,
                strlen((char *)session->peer_addr[i].ip_addr), addr_family);
        if (status != STUN_OK) goto ERROR_EXIT_PT;

        status = stun_attr_xor_peer_addr_set_port(
                        ah_attr[attr_count - 1], session->peer_addr[i].port);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    if (attr_count == 0)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No Peer addresses set for installing permission");
        return STUN_INVALID_PARAMS;
    }
    
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
                            session->realm, session->realm_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
