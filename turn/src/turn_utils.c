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

#include "types.h"
#include "msg_layer_api.h"
#include "turn_api.h"
#include "turn_int.h"

int32_t turn_utils_create_request_msg(
                            stun_method_type_t method, handle *h_msg)
{
    int32_t status;

    status = stun_msg_create(STUN_REQUEST, method, h_msg);

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

int32_t turn_utils_create_alloc_req_msg_with_credential(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status;
    uint32_t num, len;
    handle h_attr[5], h_temp, h_msg;
    u_char buf[1000];

    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_ALLOCATE, &h_msg);
    if (status != STUN_OK) return status;

    status = stun_attr_create(STUN_ATTR_USERNAME, &(h_attr[0]));
    if (status != STUN_OK) return status;

    status = stun_attr_username_set_user_name(h_attr[0], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) return status;

    status = stun_msg_add_attribute(h_msg, h_attr[0]);
    if (status != STUN_OK) return status;


    status = stun_attr_create(STUN_ATTR_NONCE, &(h_attr[1]));
    if (status != STUN_OK) return status;

    num = 1;
    status = stun_msg_get_specified_attributes(
                                session->h_resp, STUN_ATTR_NONCE, &h_temp, &num);
    if (status != STUN_OK) return status;

    len = 1000;
    status = stun_attr_nonce_get_nonce(h_temp, buf, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_nonce_set_nonce(h_attr[1], buf, len);
    if (status != STUN_OK) return status;

    status = stun_msg_add_attribute(h_msg, h_attr[1]);
    if (status != STUN_OK) return status;


    status = stun_attr_create(STUN_ATTR_REALM, &(h_attr[2]));
    if (status != STUN_OK) return status;

    num = 1;
    status = stun_msg_get_specified_attributes(
                    session->h_resp, STUN_ATTR_REALM, &h_temp, &num);
    if (status != STUN_OK) return status;

    len = 1000;
    status = stun_attr_realm_get_realm(h_temp, buf, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_realm_set_realm(h_attr[2], buf, len);
    if (status != STUN_OK) return status;

    status = stun_msg_add_attribute(h_msg, h_attr[2]);
    if (status != STUN_OK) return status;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, &(h_attr[3]));
    if (status != STUN_OK) return status;

    status = stun_attr_requested_transport_set_protocol(
                                        h_attr[3], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) return status;

    status = stun_msg_add_attribute(h_msg, h_attr[3]);
    if (status != STUN_OK) return status;

    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, &(h_attr[4]));
    if (status != STUN_OK) return status;

    status = stun_msg_add_attribute(h_msg, h_attr[4]);
    if (status != STUN_OK) return status;

    *h_newmsg = h_msg;

    return status;
}


int32_t turn_utils_extract_data_from_alloc_resp(
                                turn_session_t *session, handle h_msg)
{
    handle h_attr;
    int32_t status;
    uint32_t num, len;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_MAPPED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_mapped_addr_get_address(
                        h_attr, session->mapped_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_mapped_addr_get_port(
                                    h_attr, &(session->mapped_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only */
    session->mapped_addr.host_type = HOST_ADDR_IPV4;


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_RELAYED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_relayed_addr_get_address(
                                h_attr, session->relay_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_relayed_addr_get_port(
                                    h_attr, &(session->relay_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only */
    session->relay_addr.host_type = HOST_ADDR_IPV4;

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



#if 0
int32_t turn_utils_get_app_data_for_current_state(
                                turn_session_t *session, handle *data)
{
    switch(session->state)
    {
        case TURN_OG_ALLOCATED:
        {
            turn_alloc_resp_t *state_data;

            state_data = (turn_alloc_resp_t *) 
                        stun_malloc (sizeof(turn_alloc_resp_t));
            if (state_data == NULL)
                return STUN_MEM_ERROR;

            stun_memcpy(state_data->relay_cand_ip, 
                        session->relay_ip_addr, TURN_SVR_IP_ADDR_MAX_LEN);
            state_data->relay_cand_port = session->relay_port;

            stun_memcpy(state_data->srflx_cand_ip, 
                        session->srflx_ip_addr, TURN_SVR_IP_ADDR_MAX_LEN);
            state_data->srflx_cand_port = session->srflx_port;

            state_data->lifetime = session->lifetime;

            state_data->h_session = session;

            *data = state_data;
        }
        break;
        
        case TURN_IDLE:
        case TURN_OG_ALLOCATING:
        case TURN_OG_CREATING_PERM:
        case TURN_OG_ACTIVE:
        default:
            break;
    }

    return STUN_OK;
}
#endif


int32_t turn_session_utils_notify_state_change_event(turn_session_t *session)
{
    session->instance->state_change_cb(
                    session->instance, session,  session->state);
    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
