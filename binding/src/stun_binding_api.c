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



handle stun_bind_start_txn_timer(uint32_t duration, handle arg)
{
    handle h_txn, h_txn_inst;
    int32_t status;
    stun_binding_session_t *session;
    stun_bind_timer_params_t *timer;

    timer = (stun_bind_timer_params_t *) 
                stun_calloc (1, sizeof(stun_bind_timer_params_t));

    if (timer == NULL) return 0;

    status = stun_txn_timer_get_txn_handle(arg, &h_txn, &h_txn_inst);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    status = stun_txn_get_app_param(h_txn_inst, h_txn, (handle *)&session);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    timer->h_instance = session->instance;
    timer->h_bind_session = session;
    timer->arg = arg;
    timer->type = BIND_STUN_TXN_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);
    if (!timer->timer_id) goto ERROR_EXIT_PT;

    ICE_LOG(LOG_SEV_INFO, 
            "Started STUN BINDING transaction timer for %d msec duration. "\
            "STUN BINDING timer handle is %p", duration, timer);

    return timer;

ERROR_EXIT_PT:
    stun_free(timer);
    return 0;
}



int32_t stun_bind_stop_txn_timer(handle timer_id)
{
    stun_bind_timer_params_t *timer = (stun_bind_timer_params_t *) timer_id;
    stun_binding_session_t *session;
    int32_t status;

    if (timer_id == NULL) return STUN_INVALID_PARAMS;

    session = (stun_binding_session_t *) timer->h_bind_session;

    status = session->instance->stop_timer_cb(timer->timer_id);

    if (status == STUN_OK)
    {
        /** timer stopped successfully, so free the memory for the stun timer */
        stun_free(timer);

        ICE_LOG(LOG_SEV_INFO, 
                "Stopped STUN BINDING transaction timer with timer "\
                "id %p", timer_id);
    }
    else
    {
        ICE_LOG(LOG_SEV_INFO, 
                "Unable to stop STUN BINDING transaction timer "\
                "with timer id %p", timer_id);
    }

    return status;
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
    app_cbs.start_timer_cb = stun_bind_start_txn_timer;
    app_cbs.stop_timer_cb = stun_bind_stop_txn_timer;

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
    status = stun_binding_utils_create_msg(msg_type, &(session->h_req));

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Error while creating the stun binding message");
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
    stun_bind_timer_params_t *timer;
    stun_binding_session_t *session;

    if ((timer_id == NULL) || (arg == NULL))
        return STUN_INVALID_PARAMS;

    timer = (stun_bind_timer_params_t *) arg;
    session = (stun_binding_session_t *) timer->h_bind_session;

    if (timer->type == BIND_STUN_TXN_TIMER)
    {
        return stun_txn_inject_timer_message(timer, timer->arg, &h_txn);
    }

    /**
     * TBD - timer handling.
     * Can the timer be moved into session context, so that the timer is
     * not allocated on the heap every time which not only saves time but
     * also avoids unnecessary memory operation. The timer will be started
     * and stopped as usual but the memory will be freed only when the
     * stun binding session is destroyed.
     */

    /** stun transaction timer is the only available timer as of now */

    return STUN_INVALID_PARAMS;
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

    return status;
}



int32_t stun_binding_session_get_mapped_address(handle h_inst, 
                        handle h_session, stun_inet_addr_t *mapped_addr)
{
    stun_binding_instance_t *instance;
    stun_binding_session_t *session;
    stun_addr_family_type_t addr_family;
    handle h_attr;
    int32_t status;
    uint32_t num;

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

    num = ICE_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_mapped_addr_get_address(h_attr, 
                    &addr_family, (u_char *)mapped_addr->ip_addr, &num);
    if (status != STUN_OK) return status;

    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        mapped_addr->host_type = STUN_INET_ADDR_IPV4;
    else
        mapped_addr->host_type = STUN_INET_ADDR_IPV6;

    status = stun_attr_xor_mapped_addr_get_port(h_attr, &mapped_addr->port);

    return status;
}



int32_t stun_binding_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance)
{
    stun_bind_timer_params_t *timer;

    if ((arg == NULL) || (h_session == NULL) || (h_instance == NULL))
        return STUN_INVALID_PARAMS;

    timer = (stun_bind_timer_params_t *) arg;

    *h_session = timer->h_bind_session;
    *h_instance = timer->h_instance;

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
