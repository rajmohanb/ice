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
#include "stun_txn_api.h"
#include "stun_binding_api.h"
#include "stun_binding_int.h"
#include "stun_binding_utils.h"

int32_t stun_binding_create_instance(handle *h_inst)
{
    stun_binding_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) 
                        stun_calloc (1, sizeof(stun_binding_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    stun_memset(instance->ah_session, 0, 
            (sizeof(handle) * STUN_BINDING_MAX_CONCURRENT_SESSIONS));

    status = stun_txn_create_instance(
                    STUN_BINDING_TXN_TABLE_SIZE, &(instance->h_txn_inst));
    if (status == STUN_OK)
    {
        *h_inst = (handle) instance;
        ICE_LOG(LOG_SEV_INFO, "Stun binding instance created");
    }
    else
    {
        stun_free(instance);
        ICE_LOG(LOG_SEV_ERROR, 
                "Error while creating stun transaction instance. Stun "\
                "binding instance creation failed");
    }

    return status;
}


int32_t stun_binding_nwk_send_cb_fxn(handle h_msg, handle h_param)
{
    stun_binding_session_t *session = 
                                (stun_binding_session_t *) h_param;

    return session->instance->nwk_send_cb (h_msg, 
            session->server_type, session->stun_server, session->stun_port, 
            session->transport_param, session->app_param);
}


int32_t stun_binding_instance_set_callbacks(handle h_inst, 
                        stun_binding_instance_callbacks_t *cbs)
{
    stun_binding_instance_t *instance;
    stun_txn_instance_callbacks_t app_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (stun_binding_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;

    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = stun_binding_nwk_send_cb_fxn;
    app_cbs.start_timer_cb = cbs->start_timer_cb;
    app_cbs.stop_timer_cb = cbs->stop_timer_cb;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);

    return status;
}


int32_t stun_binding_destroy_instance(handle h_inst)
{
    stun_binding_instance_t *instance;
    int32_t i, status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;

    for (i = 0; i < STUN_BINDING_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL) continue;

        status = stun_binding_destroy_session(h_inst, instance->ah_session[i]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Destroying of stun binding session failed. "\
                    "Return value %d", status);
            goto ERROR_EXIT;
        }
    }

    status = stun_txn_destroy_instance(instance->h_txn_inst);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Destroying of stun transaction instance failed. "\
                "Return value %d", status);
        goto ERROR_EXIT;
    }

    stun_free(instance);

    return STUN_OK;

ERROR_EXIT:

    return status;
}


int32_t stun_binding_create_session(handle h_inst, 
            binding_session_type_t type, handle *h_session)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;

    session = (stun_binding_session_t *) 
                stun_calloc (1, sizeof(stun_binding_session_t));
    if (session == NULL)
        return STUN_MEM_ERROR;

    session->instance = instance;
    session->h_txn = NULL;

    for (i = 0; i < STUN_BINDING_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL)
        {
            instance->ah_session[i] = session;
            break;
        }
    }

    if (i == STUN_BINDING_MAX_CONCURRENT_SESSIONS)
    {
        stun_free(session);
        return STUN_INT_ERROR;
    }

    *h_session = session;

    return STUN_OK;
}


int32_t stun_binding_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->app_param = h_param;

    return STUN_OK;
}

int32_t stun_binding_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->transport_param = h_param;

    return STUN_OK;
}


int32_t stun_binding_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (h_param == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    /** TODO - make sure the session still exists */

    *h_param = session->app_param;

    return STUN_OK;
}

int32_t stun_binding_session_set_stun_server(handle h_inst, 
                    handle h_session, stun_inet_addr_type_t stun_srvr_type, 
                    u_char *stun_srvr, uint32_t stun_port)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (stun_srvr == NULL) || (stun_port == 0))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    for (i = 0; i < STUN_BINDING_MAX_CONCURRENT_SESSIONS; i++)
        if (instance->ah_session[i] == h_session) { break; }

    if (i == STUN_BINDING_MAX_CONCURRENT_SESSIONS) return STUN_INVALID_PARAMS;

    session->server_type = stun_srvr_type;
    stun_strncpy((char *)session->stun_server, 
                        (char *)stun_srvr, STUN_IP_ADDR_MAX_LEN - 1);
    session->stun_port = stun_port;

    return STUN_OK;
}


int32_t stun_binding_destroy_session(handle h_inst, handle h_session)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    uint32_t i;
    int32_t status = STUN_OK;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    for (i = 0; i < STUN_BINDING_MAX_CONCURRENT_SESSIONS; i++)
        if (instance->ah_session[i] == h_session) { break; }

    if (i == STUN_BINDING_MAX_CONCURRENT_SESSIONS) return STUN_INVALID_PARAMS;

    if (session->h_txn != NULL)
    {
       status = stun_destroy_txn(instance->h_txn_inst, session->h_txn, false, false);
		if (status != STUN_OK) {
        	ICE_LOG(LOG_SEV_ERROR,"Error in stun_destroy_txn()");
			/* fallthrough to free the session */
		}
    }

    stun_free(session);
    instance->ah_session[i] = NULL;

    return status;
}

int32_t stun_binding_session_send_message(handle h_inst, 
                handle h_session, stun_msg_type_t msg_type)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    int32_t status = STUN_OK;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    if (msg_type >= STUN_MSG_TYPE_MAX)
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    /** build the binding request message */
    status = stun_binding_utils_create_request_msg(&(session->h_req));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Error while creating the stun binding request message");
        return status;
    }

    status = stun_create_txn(instance->h_txn_inst, 
            STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &(session->h_txn));
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(instance->h_txn_inst, 
                                        session->h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_transport_param(instance->h_txn_inst, 
                                                    session->h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(instance->h_txn_inst, 
                                        session->h_txn, session->h_req);
    if (status != STUN_OK) return status;

    return status;
}

int32_t stun_binding_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    int32_t status;
    stun_method_type_t method;

    if ((h_inst == NULL) || (h_session == NULL) || (h_msg == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    status = stun_msg_get_method(h_msg, &method);
    if (status != STUN_OK)
        return status;

    if (method != STUN_METHOD_BINDING)
        return STUN_INVALID_PARAMS;

    /** TODO: make sure this session exists by searching in the instance */
    
    ICE_LOG(LOG_SEV_DEBUG,
		"stun_binding_session_inject_received_msg() session[%p]", session);
    session->h_resp = h_msg;

    return stun_txn_inject_received_msg(
                instance->h_txn_inst, session->h_txn, h_msg);
}


int32_t stun_binding_session_inject_timer_event(handle timer_id, handle arg)
{
    handle h_txn;

    return stun_txn_inject_timer_message(timer_id, arg, &h_txn);
}


int32_t stun_binding_instance_find_session_for_received_msg(
                            handle h_inst, handle h_msg, handle *h_session)
{
    int32_t status;
    handle h_txn, h_binding;
    stun_binding_instance_t *instance;

    if ((h_inst == NULL) || (h_msg == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;

    status = stun_txn_instance_find_transaction(
                                        instance->h_txn_inst, h_msg, &h_txn);
    if (status != STUN_OK) return STUN_NOT_FOUND;

    status = stun_txn_get_app_param(instance->h_txn_inst, h_txn, &h_binding);
    if (status != STUN_OK) return status;

    *h_session = h_binding;

    ICE_LOG(LOG_SEV_DEBUG, "*h_binding[%p]", *h_session);

    return status;
}


int32_t stun_binding_session_get_mapped_address(handle h_inst, 
        handle h_session, u_char *mapped_addr, uint32_t *len, uint32_t *port)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    stun_addr_family_type_t addr_family;
    handle h_attr;
    int32_t status, num;

    if ((h_inst == NULL) || (h_session == NULL) || (mapped_addr == NULL))
        return STUN_INVALID_PARAMS;

    instance = (stun_binding_instance_t *) h_inst;
    session = (stun_binding_session_t *) h_session;

    /** TODO - make sure the session still exists */

    if (!session->h_resp) return STUN_INVALID_PARAMS;

    num = 1;
    status = stun_msg_get_specified_attributes(
                session->h_resp, STUN_ATTR_XOR_MAPPED_ADDR, 
                &h_attr, (uint32_t *)&num);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_mapped_addr_get_address(h_attr, 
                                &addr_family, (u_char *)mapped_addr, len);
    if (status != STUN_OK) return status;

    /** TODO **/
#if 0
    if (addr_family == STUN_ADDR_FAMILY_IPV4)
#endif

    status = stun_attr_xor_mapped_addr_get_port(h_attr, port);

    return status;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
