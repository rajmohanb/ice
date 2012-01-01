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
#include "turn_api.h"
#include "turn_int.h"
#include "turn_session_fsm.h"
#include "turn_utils.h"


#define TURN_VALIDATE_SESSION_HANDLE(h_session) { \
    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++) \
        if (instance->ah_session[i] == h_session) { break; } \
\
    if (i == TURN_MAX_CONCURRENT_SESSIONS) { \
        ICE_LOG(LOG_SEV_ERROR, "Invalid TURN session handle"); \
        return STUN_INVALID_PARAMS; \
    } \
} \



int32_t turn_create_instance(handle *h_inst)
{
    turn_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) 
                        stun_calloc (1, sizeof(turn_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    stun_memset(instance->ah_session, 0, 
                        (sizeof(handle) * TURN_MAX_CONCURRENT_SESSIONS));

    status = stun_txn_create_instance(
                TURN_MAX_CONCURRENT_SESSIONS, &instance->h_txn_inst);
    if (status == STUN_OK)
    {
        *h_inst = (handle) instance;
    }

    return status;
}



int32_t turn_nwk_cb_fxn (handle h_msg, handle h_param)
{
    turn_session_t *session = (turn_session_t *) h_param;

    /** turn client always talks to the turn/stun server */

    /* TODO - what about when sending rtp data? */

    return session->instance->nwk_send_cb(h_msg, 
                    session->cfg.server.host_type,
                    session->cfg.server.ip_addr,
                    session->cfg.server.port, 
                    session->transport_param,
                    session->app_param);
}



handle turn_start_txn_timer(uint32_t duration, handle arg)
{
    handle h_txn, h_txn_inst;
    int32_t status;
    turn_session_t *session;
    turn_timer_params_t *timer;

    timer = (turn_timer_params_t *) 
        stun_calloc (1, sizeof(turn_timer_params_t));

    if (timer == NULL) return 0;

    status = stun_txn_timer_get_txn_handle(arg, &h_txn, &h_txn_inst);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    status = stun_txn_get_app_param(h_txn_inst, h_txn, (handle *)&session);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    timer->h_instance = session->instance;
    timer->h_turn_session = session;
    timer->arg = arg;
    timer->type = TURN_STUN_TXN_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    ICE_LOG(LOG_SEV_INFO, 
            "Started TURN transaction timer for %d msec duration. TURN timer "\
            "handle is %p", duration, timer);

    return timer;

ERROR_EXIT_PT:
    stun_free(timer);
    return 0;
}



int32_t turn_stop_txn_timer(handle timer_id)
{
    turn_timer_params_t *timer = (turn_timer_params_t *) timer_id;
    turn_session_t *session;
    int32_t status;

    if (timer_id == NULL)
        return STUN_INVALID_PARAMS;

    session = (turn_session_t *) timer->h_turn_session;

    status = session->instance->stop_timer_cb(timer->timer_id);

    if (status == STUN_OK)
    {
        /** timer stopped successfully, so free the memory for turn timer */
        stun_free(timer);

        ICE_LOG(LOG_SEV_INFO, 
                "Stopped TURN transaction timer with timer id %p", timer_id);
    }
    else
    {
        ICE_LOG(LOG_SEV_INFO, 
                "Unable to stop TURN transaction timer with timer id %p", 
                timer_id);
    }

    return status;
}



int32_t turn_instance_set_callbacks(handle h_inst, 
                                        turn_instance_callbacks_t *cbs)
{
    turn_instance_t *instance;
    stun_txn_instance_callbacks_t app_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (turn_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->rx_data_cb = cbs->rx_data_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;
    instance->state_change_cb = cbs->session_state_cb;

    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = turn_nwk_cb_fxn;
    app_cbs.start_timer_cb = turn_start_txn_timer;
    app_cbs.stop_timer_cb = turn_stop_txn_timer;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);

    return status;
}


int32_t turn_instance_set_client_software_name(handle h_inst, 
                                                u_char *client, uint32_t len)
{
    turn_instance_t *instance;

    if ((h_inst == NULL) || (client == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;

    instance->client_name = (u_char *) stun_calloc (1, len);
    if (instance->client_name == NULL) return STUN_MEM_ERROR;

    instance->client_name_len = len;
    stun_memcpy(instance->client_name, client, len);

    return STUN_OK;
}



int32_t turn_destroy_instance(handle h_inst)
{
    turn_instance_t *instance;
    uint32_t i;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;

    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL) continue;

        turn_destroy_session(h_inst, instance->ah_session[i]);
    }

    stun_txn_destroy_instance(instance->h_txn_inst);
    
    stun_free(instance->client_name);

    stun_free(instance);

    return STUN_OK;
}


int32_t turn_create_session(handle h_inst, handle *h_session)
{
    turn_instance_t *instance;
    turn_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;

    session = (turn_session_t *) stun_calloc (1, sizeof(turn_session_t));
    if (session == NULL)
        return STUN_MEM_ERROR;

    session->instance = instance;
    session->h_txn = NULL;
    session->state = TURN_IDLE;
    session->channel_num = 1;

    session->realm = session->nonce = NULL;
    session->alloc_refresh_timer_params = 
                session->perm_refresh_timer_params = NULL;

    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL)
        {
            instance->ah_session[i] = session;
            break;
        }
    }

    if (i == TURN_MAX_CONCURRENT_SESSIONS)
    {
        stun_free(session);
        return STUN_INT_ERROR;
    }

    *h_session = session;

    return STUN_OK;
}


int32_t turn_session_set_relay_server_cfg(handle h_inst, 
                            handle h_session, turn_server_cfg_t *server)
{
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (server == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    stun_memcpy(&session->cfg, server, sizeof(turn_server_cfg_t));

    return STUN_OK;
}


int32_t turn_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->app_param = h_param;

    return STUN_OK;
}


int32_t turn_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->transport_param = h_param;

    return STUN_OK;
}


int32_t turn_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param)
{
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    /** TODO - make sure the session still exists */

    *h_param = session->app_param;

    return STUN_OK;
}


int32_t turn_destroy_session(handle h_inst, handle h_session)
{
    int32_t i;
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    /** make sure session exists by looking up the table */
    TURN_VALIDATE_SESSION_HANDLE(h_session);

#ifdef TURN_FORCEFUL_DESTROY

    stun_free(session);
    instance->ah_session[i] = NULL;

    return STUN_OK;

#else
    return turn_session_fsm_inject_msg(session, TURN_DEALLOC_REQ, NULL);
#endif
}



int32_t turn_clear_session(handle h_inst, handle h_session)
{
    int32_t i, status;
    turn_instance_t *instance;
    turn_session_t *session;

    /** 
     * This api just frees up the memory occupied by the 
     * session ir-respective of the state the session is in.
     */
    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    /** make sure session exists by looking up the table */
    TURN_VALIDATE_SESSION_HANDLE(h_session);

    /** cleanup transactions if any */
    if (session->h_txn)
        stun_destroy_txn(instance->h_txn_inst, session->h_txn, false, false);

    /** stop timers if any and free memory for the same */
    status = turn_utils_stop_alloc_refresh_timer(session);
    if (status == STUN_OK)
        if (session->alloc_refresh_timer_params)
            stun_free(session->alloc_refresh_timer_params);

    if (session->nonce) stun_free(session->nonce);
    if (session->realm) stun_free(session->realm);

    stun_free(session);
    instance->ah_session[i] = NULL;

    return STUN_OK;
}


int32_t turn_session_allocate(handle h_inst, handle h_session)
{
    turn_session_t *session = (turn_session_t *) h_session;

    /** make sure that the session is vaild */

    return turn_session_fsm_inject_msg(session, TURN_ALLOC_REQ, NULL);
}


int32_t turn_session_create_permissions(handle h_inst, 
                                handle h_session, turn_perm_method_t method)
{
    turn_session_t *session = (turn_session_t *) h_session;

    /** make sure that the session is vaild */

    session->perm_method = method;

    return turn_session_fsm_inject_msg(session, TURN_CREATE_PERM_REQ, NULL);
}


int32_t turn_session_bind_channel(handle h_inst, 
                        handle h_session, stun_inet_addr_t *peer)
{
    /** make sure that the session is vaild */
    return STUN_OK;
}


int32_t turn_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg)
{
    turn_instance_t *instance;
    turn_session_t *session;
    turn_event_t event;
    int32_t status = STUN_OK;
    stun_method_type_t method;
    stun_msg_type_t class;

    if ((h_inst == NULL) || (h_session == NULL) || (h_msg == NULL))
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] Invalid parameters provided while injecting "\
                "received message for turn");
        return STUN_INVALID_PARAMS;
    }

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    status = stun_msg_get_class(h_msg, &class);
    if (status != STUN_OK)
        return status;

    status = stun_msg_get_method(h_msg, &method);
    if (status != STUN_OK)
        return status;

    switch(method)
    {
        case STUN_METHOD_ALLOCATE:
        {
            if (class == STUN_REQUEST)
            {
                /** a turn client does not handle incoming ALLOCATE requests */
                event = TURN_ALLOC_REQ;
                status = STUN_INVALID_PARAMS;
            }
            else if ((class == STUN_SUCCESS_RESP) ||
                     (class == STUN_ERROR_RESP))
            {
                event = TURN_ALLOC_RESP;
            }
            else 
            {
                status = STUN_INVALID_PARAMS;
            }
            break;
        }

        case STUN_METHOD_REFRESH:
        {
            if (class == STUN_REQUEST)
            {
                /** a turn client does not handle incoming REFRESH requests */
                event = TURN_REFRESH_REQ;
                status = STUN_INVALID_PARAMS;
            }
            else if ((class == STUN_SUCCESS_RESP) ||
                     (class == STUN_ERROR_RESP))
            {
                event = TURN_REFRESH_RESP;
            }
            else 
            {
                status = STUN_INVALID_PARAMS;
            }
            
            break;
        }

        case STUN_METHOD_CREATE_PERMISSION:
        {
            if (class == STUN_REQUEST)
            {
                /** a turn client does not handle incoming REFRESH requests */
                event = TURN_CREATE_PERM_REQ;
                status = STUN_INVALID_PARAMS;
            }
            else if ((class == STUN_SUCCESS_RESP) ||
                     (class == STUN_ERROR_RESP))
            {
                event = TURN_CREATE_PERM_RESP;
            }
            else 
            {
                status = STUN_INVALID_PARAMS;
            }
            
            break;
        }

        case STUN_METHOD_DATA:
            event = TURN_DATA_IND;
            break;

        case STUN_METHOD_SEND:
        case STUN_METHOD_CHANNEL_BIND:
        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    if (status != STUN_OK) return status;

    /** TODO: make sure this session exists by searching in the instance */
    
    session->h_resp = h_msg;

    return turn_session_fsm_inject_msg(session, event, h_msg);
}



int32_t turn_instance_find_session_for_received_msg(handle h_inst, 
                                        handle h_msg, handle *h_session)
{
    int32_t status;
    handle h_txn, h_turn;
    turn_instance_t *instance;

    if ((h_inst == NULL) || (h_msg == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;

    status = stun_txn_instance_find_transaction(
                                        instance->h_txn_inst, h_msg, &h_txn);

    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_DEBUG, 
            "unable to find transaction for the received "\
            " message. status %d", status);
        return STUN_NOT_FOUND;
    }
    else
    {
        ICE_LOG(LOG_SEV_DEBUG, "Found an existing turn session");
    }

    status = stun_txn_get_app_param(instance->h_txn_inst, h_txn, &h_turn);
    if (status != STUN_OK) return status;

    *h_session = h_turn;

    return status;
}



int32_t turn_session_inject_timer_message(handle h_timerid, handle h_timer_arg)
{
    int32_t status;
    handle h_txn;
    turn_timer_params_t *timer;
    turn_session_t *session;

    if ((h_timerid == NULL) || (h_timer_arg == NULL))
        return STUN_INVALID_PARAMS;

    timer = (turn_timer_params_t *) h_timer_arg;
    session = (turn_session_t *)timer->h_turn_session;

    /** make sure we have the session alive before injecting the event */
    status = turn_table_validate_session_handle(
                        timer->h_instance, timer->h_turn_session);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_INFO, 
            "[TURN] Some stray TURN timer. Ignoring for now");
        stun_free(timer);
        return STUN_OK;
    }

    switch (timer->type)
    {
        case TURN_STUN_TXN_TIMER:
        {
            status = stun_txn_inject_timer_message(timer, timer->arg, &h_txn);
            if (status == STUN_TERMINATED)
            {
                /** turn associated transaction timed out */
                status = turn_session_fsm_inject_msg(
                                        session, TURN_TXN_TIMEOUT, h_txn);
            }

            stun_free(timer);
            break;
        }

        case TURN_ALLOC_REFRESH_TIMER:
            status= turn_session_fsm_inject_msg(
                                        session, TURN_ALLOC_REFRESH_EXPIRY, NULL);
            break;

        case TURN_PERM_REFRESH_TIMER:
            status= turn_session_fsm_inject_msg(
                                        session, TURN_PERM_REFRESH_EXPIRY, NULL);
            break;

        case TURN_CHNL_REFRESH_TIMER:
            status= turn_session_fsm_inject_msg(
                                        session, TURN_CHNL_REFRESH_EXPIRY, NULL);
            break;

        case TURN_KEEP_ALIVE_TIMER:
            status= turn_session_fsm_inject_msg(
                                        session, TURN_KEEP_ALIVE_EXPIRY, NULL);
            break;

        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    return status;
}



int32_t turn_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance)
{
    turn_timer_params_t *timer;

    if ((arg == NULL) || (h_session == NULL) || (h_instance == NULL))
        return STUN_INVALID_PARAMS;

    timer = (turn_timer_params_t *) arg;

    *h_session = timer->h_turn_session;
    *h_instance = timer->h_instance;

    return STUN_OK;
}



int32_t turn_session_get_allocation_info(handle h_inst, 
                        handle h_session, turn_session_alloc_info_t *info)
{
    turn_instance_t *instance;
    turn_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (info == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    info->lifetime = session->lifetime;

    stun_memcpy(&info->relay_addr, 
            &session->relay_addr, sizeof(stun_inet_addr_t));

    stun_memcpy(&info->mapped_addr, 
            &session->mapped_addr, sizeof(stun_inet_addr_t));

    return STUN_OK;
}



int32_t turn_session_add_peer_address(handle h_inst, 
                                    handle h_session, stun_inet_addr_t *addr)
{
    int32_t i;
    turn_instance_t *instance;
    turn_session_t *session;
    turn_permission_t *perm;

    if ((h_inst == NULL) || (h_session == NULL) || (addr == NULL))
        return STUN_INVALID_PARAMS;

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    for (i = 0; i< TURN_MAX_PERMISSIONS; i++)
    {
        if (session->aps_perms[i] != NULL) continue;

        perm = (turn_permission_t *) stun_calloc(1, sizeof(turn_permission_t));
        if (perm == NULL) return STUN_MEM_ERROR;

        stun_memcpy(&perm->peer_addr, addr, sizeof(stun_inet_addr_t));

#if 0
        /** By default, always use data/send indication? */
        perm->use_channel = false;
#endif

        perm->h_perm_chnl_refresh = NULL;
        perm->perm_chnl_refresh_timer_params = NULL;
        perm->h_chnl_txn = perm->h_chnl_req = perm->h_chnl_resp = NULL;

        session->aps_perms[i] = perm;

        return STUN_OK;
    }

    return STUN_NO_RESOURCE;
}



/** 
 * TODO This api must take the transport type also in addition to 
 * stun_inet_addr_t. Better to re-use ice_transport_t?
 */
int32_t turn_session_send_application_data(handle h_inst, 
                            handle h_session, stun_inet_addr_t *peer_dest,
                            u_char *data, uint32_t len)
{
    turn_instance_t *instance;
    turn_session_t *session;
    turn_app_data_t app_data;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    /** the data can be empty, and is legal! */

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    app_data.data = data;
    app_data.len = len;
    app_data.dest = peer_dest;

    return turn_session_fsm_inject_msg(session, TURN_SEND_IND, &app_data);
}


int32_t turn_session_get_application_data(handle h_inst, 
        handle h_session, stun_inet_addr_t *peer_src, u_char *data, uint32_t len)
{
    turn_instance_t *instance;
    turn_session_t *session;
    turn_app_data_t app_data;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (peer_src == NULL) || (data == NULL))
        return STUN_INVALID_PARAMS;

    /** the data can be empty, and is legal! */

    instance = (turn_instance_t *) h_inst;
    session = (turn_session_t *) h_session;

    app_data.data = data;
    app_data.len = len;
    app_data.dest = peer_src;

    return turn_session_fsm_inject_msg(session, TURN_DATA_IND, &app_data);
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
