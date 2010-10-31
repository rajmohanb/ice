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
#include "conn_check_session_fsm.h"
#include "conn_check_utils.h"


    
int32_t conn_check_create_instance(handle *h_inst)
{
    conn_check_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) 
                        stun_calloc (1, sizeof(conn_check_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    status = stun_txn_create_instance(
                        CONN_CHECK_TXN_TABLE_SIZE, &instance->h_txn_inst);
    if (status == STUN_OK)
    {
        *h_inst = (handle) instance;
    }
    else
    {
        stun_free(instance);
    }

    return status;
}


int32_t cc_nwk_send_cb_fxn(handle h_msg, handle h_param)
{
    conn_check_session_t *session = (conn_check_session_t *) h_param;

    return session->instance->nwk_send_cb (h_msg, 
            session->stun_server_type, session->stun_server, 
            session->stun_port, session->transport_param, session->app_param);
}


handle cc_start_timer(uint32_t duration, handle arg)
{
    handle h_txn, h_txn_inst;
    int32_t status;
    conn_check_session_t *session;
    cc_timer_params_t *timer;

    timer = (cc_timer_params_t *) 
        stun_calloc (1, sizeof(cc_timer_params_t));

    if (timer == NULL)
        return 0;

    status = stun_txn_timer_get_txn_handle(arg, &h_txn, &h_txn_inst);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_txn_get_app_param(h_txn_inst, h_txn, (handle)&session);
    if (status != STUN_OK) goto ERROR_EXIT;

    timer->h_instance = session->instance;
    timer->h_cc_session = session;
    timer->arg = arg;
    timer->type = CC_STUN_TXN_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    return timer;

ERROR_EXIT:
    stun_free(timer);
    return 0;
}


int32_t cc_stop_timer(handle timer_id)
{
    cc_timer_params_t *timer = (cc_timer_params_t *) timer_id;
    conn_check_session_t *session;
    int32_t status;

    if (timer_id == NULL)
        return STUN_INVALID_PARAMS;

    session = (conn_check_session_t *) timer->h_cc_session;

    status = session->instance->stop_timer_cb(timer->timer_id);

    if (status == STUN_OK)
    {
        /** timer stopped successfully, so free the memory for turn timer */
        stun_free(timer);
    }

    return status;
}


int32_t conn_check_instance_set_callbacks(
                handle h_inst, conn_check_instance_callbacks_t *cbs)
{
    conn_check_instance_t *instance;
    stun_txn_instance_callbacks_t app_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (conn_check_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;
    instance->state_change_cb = cbs->session_state_cb;

    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = cc_nwk_send_cb_fxn;
    app_cbs.start_timer_cb = cc_start_timer;
    app_cbs.stop_timer_cb = cc_stop_timer;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);

    return status;
}


int32_t conn_check_instance_set_client_software_name(handle h_inst, 
                                                u_char *client, uint32_t len)
{
    conn_check_instance_t *instance;

    if ((h_inst == NULL) || (client == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;

    instance->client_name = (u_char *) stun_calloc (1, len);
    if (instance->client_name == NULL) return STUN_MEM_ERROR;

    instance->client_name_len = len;
    stun_memcpy(instance->client_name, client, len);

    return STUN_OK;
}


int32_t conn_check_destroy_instance(handle h_inst)
{
    conn_check_instance_t *instance;
    uint32_t i;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;

    for (i = 0; i < CONN_CHECK_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL) continue;

        conn_check_destroy_session(h_inst, instance->ah_session[i]);
    }

    stun_txn_destroy_instance(instance->h_txn_inst);

    stun_free(instance->client_name);

    stun_free(instance);

    return STUN_OK;
}


int32_t conn_check_create_session(handle h_inst, 
                cc_session_type_t sess_type, handle *h_session)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    if (sess_type >= CC_SESSION_TYPE_MAX)
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;

    session = (conn_check_session_t *) 
                    stun_calloc (1, sizeof(conn_check_session_t));
    if (session == NULL)
        return STUN_MEM_ERROR;

    session->instance = instance;
    session->h_txn = NULL;
    session->sess_type = sess_type;
    if (sess_type == CC_CLIENT_SESSION)
        session->state = CC_OG_IDLE;
    else
        session->state = CC_IC_IDLE;

    for (i = 0; i < CONN_CHECK_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->ah_session[i] == NULL)
        {
            instance->ah_session[i] = session;
            break;
        }
    }

    if (i == CONN_CHECK_MAX_CONCURRENT_SESSIONS)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "Number of simultaneous connectivity check sessions exceeded");
        stun_free(session);
        return STUN_NO_RESOURCE;
    }

    session->nominated = false;
    session->controlling_role = false;
    session->prflx_cand_priority = 0;
    session->cc_succeeded = false;
    session->error_code = 0;

    *h_session = session;

    return STUN_OK;
}


int32_t conn_check_session_set_peer_transport_params(
        handle h_inst, handle h_session, stun_inet_addr_type_t stun_svr_type, 
        u_char *stun_svr_ip, uint32_t port)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (stun_svr_ip == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session exists */
    
    session->stun_server_type = stun_svr_type;
    stun_memcpy(session->stun_server, stun_svr_ip, STUN_IP_ADDR_MAX_LEN);
    session->stun_port = port;

    return STUN_OK;
}


int32_t conn_check_session_set_local_credentials(handle h_inst, 
                handle h_session, conn_check_credentials_t *cred)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (cred == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session exists */

    stun_strncpy((char *)session->local_user, 
                    (char *)cred->username, STUN_MAX_USERNAME_LEN - 1);
    stun_strncpy((char *)session->local_pwd, 
                    (char *)cred->password, STUN_MAX_PASSWORD_LEN - 1);
    session->local_user_len = stun_strlen((char *)cred->username);
    session->local_pwd_len = stun_strlen((char *)cred->password);

    return STUN_OK;
}


int32_t conn_check_session_set_peer_credentials(handle h_inst, 
                handle h_session, conn_check_credentials_t *cred)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (cred == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session exists */

    stun_strncpy((char *)session->peer_user, 
                    (char *)cred->username, STUN_MAX_USERNAME_LEN - 1);
    stun_strncpy((char *)session->peer_pwd, 
                    (char *)cred->password, STUN_MAX_PASSWORD_LEN - 1);
    session->peer_user_len = stun_strlen((char *)cred->username);
    session->peer_pwd_len = stun_strlen((char *)cred->password);

    return STUN_OK;
}


int32_t conn_check_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->app_param = h_param;

    return STUN_OK;
}

int32_t conn_check_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->transport_param = h_param;

    return STUN_OK;
}


int32_t conn_check_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session still exists */

    *h_param = session->app_param;

    return STUN_OK;
}

int32_t conn_check_session_set_session_params(handle h_inst, 
                        handle h_session, conn_check_session_params_t *params)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    /** TODO - make sure the session still exists */

    session->nominated = params->nominated;
    session->controlling_role = params->controlling_role;
    session->prflx_cand_priority = params->prflx_cand_priority;

    return STUN_OK;
}

int32_t conn_check_destroy_session(handle h_inst, handle h_session)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    for (i = 0; i < CONN_CHECK_MAX_CONCURRENT_SESSIONS; i++)
        if (instance->ah_session[i] == h_session) { break; }

    if (i == CONN_CHECK_MAX_CONCURRENT_SESSIONS) { return STUN_INVALID_PARAMS; }

    if (session->h_txn != NULL)
    {
        stun_destroy_txn(instance->h_txn_inst, session->h_txn, false, false);
    }

    stun_free(session);
    instance->ah_session[i] = NULL;

    return STUN_OK;
}

int32_t conn_check_session_initiate_check(handle h_inst, handle h_session)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;
    int32_t status = STUN_OK;
    conn_check_session_state_t cur_state;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    if (session->sess_type != CC_CLIENT_SESSION)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[CONN CHECK] Invalid session type for initiating "\
                "connectivity checks");
        return STUN_INVALID_PARAMS;
    }

    cur_state = session->state;
    status = conn_check_session_fsm_inject_msg(session, CONN_CHECK_REQ, NULL);

    if (cur_state != session->state)
        instance->state_change_cb(h_inst, h_session, session->state, NULL);

    return status;
}



int32_t conn_check_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg)
{
    conn_check_instance_t *instance;
    conn_check_session_t *session;
    conn_check_event_t event;
    int32_t status = STUN_OK;

    stun_method_type_t method;
    stun_msg_type_t class;
    conn_check_session_state_t cur_state;

    if ((h_inst == NULL) || (h_session == NULL) || (h_msg == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;
    session = (conn_check_session_t *) h_session;

    status = stun_msg_get_class(h_msg, &class);
    if (status != STUN_OK)
        return status;

    status = stun_msg_get_method(h_msg, &method);
    if (status != STUN_OK)
        return status;

    if (method != STUN_METHOD_BINDING)
        return STUN_INVALID_PARAMS;

    switch(class)
    {
        case STUN_REQUEST:
            event = CONN_CHECK_REQ;
            break;

        case STUN_SUCCESS_RESP:
            event = CONN_CHECK_OK_RESP;
            break;

        case STUN_ERROR_RESP:
            event = CONN_CHECK_ERROR_RESP;
            break;

        case STUN_INDICATION:
        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    if (status != STUN_OK) return status;

    /** TODO: make sure this session exists by searching in the instance */
    
    session->h_resp = h_msg;

    cur_state = session->state;
    return conn_check_session_fsm_inject_msg(session, event, h_msg);
}



int32_t conn_check_instance_inject_timer_event(
                    handle h_timerid, handle arg, handle *h_session)
{
    handle h_txn;
    int32_t status;
    cc_timer_params_t *timer;
    conn_check_session_t *session;

    if ((h_timerid == NULL) || (arg == NULL))
        return STUN_INVALID_PARAMS;

    timer = (cc_timer_params_t *) arg;
    session = (conn_check_session_t *)timer->h_cc_session;

    switch (timer->type)
    {
        case CC_STUN_TXN_TIMER:
        {
            status = stun_txn_inject_timer_message(timer, timer->arg, &h_txn);
            if (status == STUN_TERMINATED)
            {
                /** connectivity check transaction timed out */
                status = conn_check_session_fsm_inject_msg(
                                        session, CONN_CHECK_TIMER, h_txn);
            }
            *h_session = (handle) session;
            break;
        }

        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    return status;
}



int32_t conn_check_find_session_for_recv_msg(handle h_inst, 
                                        handle h_msg, handle *h_session)
{
    int32_t status;
    handle h_txn, h_cc;
    conn_check_instance_t *instance;

    if ((h_inst == NULL) || (h_msg == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (conn_check_instance_t *) h_inst;

    status = stun_txn_instance_find_transaction(
                                        instance->h_txn_inst, h_msg, &h_txn);
    if (status != STUN_OK) return STUN_NOT_FOUND;

    status = stun_txn_get_app_param(instance->h_txn_inst, h_txn, &h_cc);
    if (status != STUN_OK) return status;

    *h_session = h_cc;

    return status;
}


int32_t conn_check_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance)
{
    cc_timer_params_t *timer;

    if ((arg == NULL) || (h_session == NULL) || (h_instance == NULL))
        return STUN_INVALID_PARAMS;

    timer = (cc_timer_params_t *) arg;

    *h_session = timer->h_cc_session;
    *h_instance = timer->h_instance;

    return STUN_OK;
}


int32_t conn_check_session_get_check_result(handle h_inst, 
                            handle h_session, conn_check_result_t *result)
{
    conn_check_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (result == NULL))
        return STUN_INVALID_PARAMS;

    session = (conn_check_session_t *) h_session;

    if ((session->state != CC_OG_TERMINATED) && 
            (session->state != CC_IC_TERMINATED))
        return STUN_INVALID_PARAMS;

    result->check_succeeded = session->cc_succeeded;
    result->controlling_role = session->controlling_role;
    result->error_code = session->error_code;
    result->nominated = session->nominated;
    result->prflx_priority = session->prflx_cand_priority;

    stun_memcpy(&result->prflx_addr,
                    &session->prflx_addr, sizeof(stun_inet_addr_t));

    return STUN_OK;
}




/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
