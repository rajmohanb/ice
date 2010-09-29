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
#include "stun_enc_dec_api.h"
#include "conn_check_api.h"
#include "turn_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_session_fsm.h"
#include "ice_utils.h"



#define ICE_VALIDATE_SESSION_HANDLE(h_session) { \
    for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++) \
        if (instance->aps_sessions[i] == h_session) { break; } \
\
    if (i == ICE_MAX_CONCURRENT_SESSIONS) { \
        ICE_LOG(LOG_SEV_ERROR, "Invalid session handle"); \
        return STUN_INVALID_PARAMS; \
    } \
} \


static char* turn_states[] = 
{
    "TURN_IDLE",
    "TURN_OG_ALLOCATING",
    "TURN_OG_ALLOCATED",
    "TURN_OG_CREATING_PERM",
    "TURN_OG_ACTIVE",
    "TURN_OG_DEALLOCATING",
    "TURN_OG_FAILED",
};



int32_t ice_create_instance(handle *h_inst)
{
    ice_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) 
                        stun_calloc (1, sizeof(ice_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;
    status = turn_create_instance(&instance->h_turn_inst);
    if (status != STUN_OK)
    {
        stun_free(instance);
        return status;
    }

    status = conn_check_create_instance(&instance->h_cc_inst);
    if (status != STUN_OK)
    {
       stun_free(instance);
        return status;
    }

    *h_inst = (handle) instance;

    return status;
}


void ice_turn_callback_fxn (handle h_turn_inst, 
        handle h_turn_session, turn_session_state_t turn_session_state)
{
    int32_t status;
    ice_media_stream_t *media;
    ice_session_event_t event;
    ice_int_params_t event_params= {0};

    if ((h_turn_inst == NULL) || (h_turn_session == NULL))
    {
        ICE_LOG(LOG_SEV_ERROR, "Invalid parameters received in turn "\
                "callback routine. Null turn instance/session handle");
        return;
    }

    ICE_LOG(LOG_SEV_DEBUG, "TURN session state changed to %s for "\
            "turn session %p", turn_states[turn_session_state], h_turn_session);

    switch(turn_session_state)
    {
        case TURN_OG_ALLOCATED:
            event = ICE_GATHERED_CANDS;
            break;

        case TURN_OG_FAILED:
            event = ICE_GATHER_FAILED;
            break;

        /** we are not interested in other states */
        case TURN_OG_ALLOCATING:
        case TURN_OG_CREATING_PERM:
        case TURN_OG_ACTIVE:
        case TURN_OG_DEALLOCATING:
        default:
            event = ICE_SES_EVENT_MAX;
            break;
    }

    if (event == ICE_SES_EVENT_MAX)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "Ignoring turn session state %d", turn_session_state);
        return;
    }

    event_params.h_inst = h_turn_inst;
    event_params.h_session = h_turn_session;

    /** get the ice session handle who owns this turn session */
    status = turn_session_get_app_param(
                        h_turn_inst, h_turn_session, (handle *)&media);

    status = ice_session_fsm_inject_msg(
                    media->ice_session, event, &event_params, NULL);

    return;
}


void ice_cc_callback_fxn (handle h_cc_inst, 
        handle h_cc_session, conn_check_session_state_t state, handle data)
{
    int32_t status;
    ice_session_event_t event;
    handle h_session;
    ice_session_t *session;

    if ((h_cc_inst == NULL) || (h_cc_session == NULL))
    {
        ICE_LOG (LOG_SEV_ERROR, "FIXME: parameters not valid\n");
        return;
    }

    switch(state)
    {
        case CC_OG_IDLE:
        case CC_OG_CHECKING:
        case CC_OG_INPROGRESS:
            break;

        case CC_OG_TERMINATED:
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "Outgoing connectivity check terminated");

            /** declare success now? TODO - check if it is success */
            event = ICE_CONN_CHECKS_DONE;
        }
        break;

        case CC_IC_IDLE:
        break;

        case CC_IC_TERMINATED:
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "*******************************************************************\n\n");
            ICE_LOG (LOG_SEV_DEBUG,
                    "Incoming connectivity check terminated");
            ICE_LOG (LOG_SEV_DEBUG, 
                    "\n\n*******************************************************************\n\n");

            /** feed this into the fsm */
            /* event = ICE_IC_CONN_CHECK; */
        }
        break;

        default:
            event = ICE_SES_EVENT_MAX;
            break;
    }

    if ((state == CC_OG_TERMINATED) || (state == CC_IC_TERMINATED))
    {
        /** get the ice session handle who owns this turn session */
        status = conn_check_session_get_app_param(
                                h_cc_inst, h_cc_session, &h_session);

        session = (ice_session_t *) h_session;

        status = ice_session_fsm_inject_msg(session, event, data, NULL);
    }

    return;
}


handle ice_turn_start_timer(uint32_t duration, handle arg)
{
    int32_t status;
    ice_timer_params_t *timer;
    handle h_turn_session, h_turn_inst;
    ice_media_stream_t *media;

    timer = (ice_timer_params_t *) 
        stun_calloc (1, sizeof(ice_timer_params_t));
    if (timer == NULL) return 0;

    status = turn_session_timer_get_session_handle(
                                        arg, &h_turn_session, &h_turn_inst);
    if (status != STUN_OK) return 0;

    status = turn_session_get_app_param( 
                            h_turn_inst, h_turn_session, (handle *)&media);
    if (status != STUN_OK) return 0;

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->arg = arg;
    timer->type = ICE_TURN_TIMER;

    timer->timer_id = 
        media->ice_session->instance->start_timer_cb(duration, timer);
    if (timer->timer_id)
        return timer;
    else 
        return 0;
}


handle ice_cc_start_timer(uint32_t duration, handle arg)
{
    int32_t status;
    ice_timer_params_t *timer;
    handle h_cc_session, h_cc_inst;
    ice_media_stream_t *media;

    timer = (ice_timer_params_t *) 
        stun_calloc (1, sizeof(ice_timer_params_t));
    if (timer == NULL) return 0;

    status = conn_check_session_timer_get_session_handle(
                                        arg, &h_cc_session, &h_cc_inst);
    if (status != STUN_OK)
    {
        goto ERROR_EXIT;
    }

    status = conn_check_session_get_app_param( 
                            h_cc_inst, h_cc_session, (handle *)&media);
    if (status != STUN_OK)
    {
        goto ERROR_EXIT;
    }

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->h_media = media;
    timer->arg = arg;
    timer->type = ICE_CC_TIMER;

    timer->timer_id = media->ice_session->instance->start_timer_cb(duration, timer);
    if (timer->timer_id)
    {
        return timer;
    }
    
ERROR_EXIT:
    stun_free(timer);
    return 0;
}


int32_t ice_stop_timer(handle timer_id)
{
    ice_timer_params_t *timer = (ice_timer_params_t *) timer_id;
    ice_session_t *session;
    int32_t status;

    if (timer_id == NULL)
        return STUN_INVALID_PARAMS;

    session = (ice_session_t *) timer->h_session;

    status = session->instance->stop_timer_cb(timer->timer_id);

    if (status == STUN_OK)
    {
        /** timer stopped successfully, so free the memory for turn timer */
        stun_free(timer);
    }

    return status;
}


int32_t ice_format_and_send_message(handle h_msg, 
                stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                uint32_t port, handle transport_param, handle app_param)
{
    u_char *buf;
    uint32_t sent_bytes, buf_len, status;
    int32_t sock_fd = (int32_t) transport_param;
    ice_media_stream_t *media = (ice_media_stream_t *) app_param;
    ice_session_t *ice_session;
    stun_auth_params_t auth = {0};

    if ((h_msg == NULL) || (ip_addr == NULL) || 
                            (port == 0) || (transport_param == NULL))
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "Invalid parameter, hence not sending message");
        return STUN_INVALID_PARAMS;
    }

    /** for ice_lite, this wil always be a connectivity check session */
    if (!app_param) return STUN_INT_ERROR;

    ice_session = media->ice_session;

    buf = (u_char *) platform_calloc(1, TRANSPORT_MTU_SIZE);
    buf_len = TRANSPORT_MTU_SIZE;

    /** authentication parameters for message integrity */
    auth.len = strlen(media->local_pwd);
    if(auth.len > STUN_MSG_AUTH_PASSWORD_LEN)
        auth.len = STUN_MSG_AUTH_PASSWORD_LEN;

    stun_strncpy((char *)auth.password, media->local_pwd, auth.len);

    status = stun_msg_encode(h_msg, &auth, buf, &buf_len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "stun_msg_format() returned error %d\n", status);
        return STUN_INT_ERROR;
    }

    if (!sock_fd)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "some error! transport socket handle is NULL\n");
        return STUN_INVALID_PARAMS;
    }

    sent_bytes = ice_session->instance->nwk_send_cb(buf, 
            buf_len, ip_addr_type, ip_addr, port, transport_param);

    stun_free(buf);

    if (sent_bytes == -1)
        return STUN_INT_ERROR;
    else
        return STUN_OK;
}


int32_t ice_instance_set_callbacks(handle h_inst, 
                                        ice_instance_callbacks_t *cbs)
{
    ice_instance_t *instance;
    conn_check_instance_callbacks_t cc_cbs;
    turn_instance_callbacks_t turn_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (ice_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;
    
    /** set callbacks to turn module */
    turn_cbs.nwk_cb = ice_format_and_send_message;
    turn_cbs.start_timer_cb = ice_turn_start_timer;
    turn_cbs.stop_timer_cb = ice_stop_timer;

    /** set callback function for turn session state */
    turn_cbs.session_state_cb = ice_turn_callback_fxn;

    status = turn_instance_set_callbacks(instance->h_turn_inst, &turn_cbs);
    if (status != STUN_OK)
    {
        return status;
    }
    /** set callbacks to connectivity check module */
    cc_cbs.nwk_cb = ice_format_and_send_message;
    cc_cbs.start_timer_cb = ice_cc_start_timer;
    cc_cbs.stop_timer_cb = ice_stop_timer;

    /** set callback function for conn check session state */
    cc_cbs.session_state_cb = ice_cc_callback_fxn;

    status = conn_check_instance_set_callbacks(instance->h_cc_inst, &cc_cbs);
    if (status != STUN_OK)
    {
        return status;
    }

    return status;
}


int32_t ice_instance_register_event_handlers(handle h_inst, 
                        ice_state_event_handlers_t *event_handlers)
{
    ice_instance_t *instance;

    if ((h_inst == NULL) || (event_handlers == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    instance->session_state_event_cb = event_handlers->session_state_cb;
    instance->media_state_event_cb = event_handlers->media_state_cb;
    
    return STUN_OK;
}



int32_t ice_set_client_software_name(handle h_inst, u_char *name)
{
    ice_instance_t *instance;

    if ((h_inst == NULL) || (name == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    stun_strncpy((char *)instance->client, 
            (char *)name, (SOFTWARE_CLIENT_NAME_LEN - 1));

    /** TODO: propagate to turn instance */

    return STUN_OK;
}


int32_t ice_destroy_instance(handle h_inst)
{
    ice_instance_t *instance;
    uint32_t i;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->aps_sessions[i] == NULL) continue;

        ice_destroy_session(h_inst, instance->aps_sessions[i]);
    }

    conn_check_destroy_instance(instance->h_cc_inst);

    stun_free(instance);

    return STUN_OK;
}


int32_t ice_create_session(handle h_inst, 
                           ice_session_type_t ice_sess_type, 
                           ice_mode_type_t mode, handle *h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    if ((ice_sess_type != ICE_SESSION_OUTGOING) &&
        (ice_sess_type != ICE_SESSION_INCOMING))
        return STUN_INVALID_PARAMS;

    if ((mode != ICE_MODE_LITE) && (mode != ICE_MODE_FULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    session = (ice_session_t *) 
                    stun_calloc (1, sizeof(ice_session_t));
    if (session == NULL)
        return STUN_MEM_ERROR;

    session->instance = instance;

    for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (instance->aps_sessions[i] == NULL)
        {
            instance->aps_sessions[i] = (handle)session;
            break;
        }
    }

    if (i == ICE_MAX_CONCURRENT_SESSIONS)
    {
        stun_free(session);
        return STUN_INT_ERROR;
    }

    session->local_mode = mode;

    if (session->local_mode == ICE_MODE_FULL)
    {
        if (ice_sess_type == ICE_SESSION_OUTGOING)
            session->role = ICE_AGENT_ROLE_CONTROLLING;
        else 
            session->role = ICE_AGENT_ROLE_CONTROLLED;
    }
    else
    {
        session->role = ICE_AGENT_ROLE_CONTROLLED;
    }

    session->state = ICE_SES_IDLE;
    session->peer_mode = ICE_INVALID_MODE;

    *h_session = session;

    ICE_LOG(LOG_SEV_DEBUG, "ICE session created successfully");

    return STUN_OK;
}



int32_t ice_session_set_relay_server_cfg(handle h_inst, 
                                handle h_session, ice_relay_server_cfg_t *relay)
{
    int32_t i, status = STUN_OK;
    ice_instance_t *instance;
    ice_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (relay == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    stun_memcpy(&session->turn_cfg, relay, sizeof(ice_relay_server_cfg_t));

    if (session->turn_cfg.server.port == 0)
        session->turn_cfg.server.port = TURN_SERVER_DEFAULT_PORT;

    return status;
}



int32_t ice_session_set_stun_server_cfg(handle h_inst, 
                                handle h_session, ice_stun_server_cfg_t *stun)
{
    int32_t i;
    ice_instance_t *instance;
    ice_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (stun == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    stun_memcpy(&session->stun_cfg, stun, sizeof(ice_stun_server_cfg_t));

    if (session->stun_cfg.server.port == 0)
        session->stun_cfg.server.port = STUN_SERVER_DEFAULT_PORT;

#if 0
    /** TODO - propagate this configuration to stun binding module */
#endif

    return STUN_OK;
}



int32_t ice_destroy_session(handle h_inst, handle h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    uint32_t i, j;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    /** clean up media */
    for (j = 0; j < ICE_MAX_MEDIA_STREAMS; j++)
    {
        if (session->aps_media_streams[j])
        {
            ice_session_remove_media_stream(h_inst, 
                            h_session, session->aps_media_streams[j]);
        }
    }

#if 0
    instance->aps_sessions[i] = NULL;
    stun_free(session);
#endif

    return STUN_OK;
}


int32_t ice_session_add_media_stream (handle h_inst, handle h_session, 
                        ice_api_media_stream_t *media, handle *h_media)
{
    int32_t i;
    ice_instance_t *instance;
    ice_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) || (media == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    if (session->num_media_streams >= ICE_MAX_MEDIA_STREAMS)
    {
        ICE_LOG(LOG_SEV_ERROR, "Adding of media stream failed. "\
               "Maximum allowed media streams per session already reached.");
        return STUN_NO_RESOURCE;
    }

    return ice_session_fsm_inject_msg(session, ICE_ADD_MEDIA, media, h_media);
}


int32_t ice_session_remove_media_stream (handle h_inst,
                                handle h_session, handle h_media)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || (h_media == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    return ice_session_fsm_inject_msg(session, 
                                        ICE_REMOVE_MEDIA, h_media, NULL);
}


int32_t ice_session_gather_candidates(handle h_inst, handle h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    return ice_session_fsm_inject_msg(session, 
                                        ICE_INIT_GATHERING, NULL, NULL);
}


int32_t ice_session_get_session_params(handle h_inst, 
                handle h_session, ice_session_params_t *session_params)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    ice_media_params_t *media_params;
    int32_t i, status;

    if ((h_inst == NULL) || (h_session == NULL) || (session_params == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    session_params->ice_mode = session->local_mode;
    session_params->num_media = 0;

    for (i = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        media = session->aps_media_streams[i];
        if (!media) continue;

        media_params = &session_params->media[session_params->num_media];
        memset(media_params, 0, sizeof(ice_media_params_t));

        status = ice_utils_get_local_media_params(media, media_params);
        if(status != STUN_OK) break;

        session_params->num_media += 1;

#ifdef DEBUG
        if (status == STUN_OK)
            ice_utils_dump_media_params(media_params);
#endif
    }

    return status;
}


int32_t ice_session_get_media_params(handle h_inst, 
        handle h_session, handle h_media, ice_media_params_t *media_params)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i, status;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (h_media == NULL) || (media_params == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    media = (ice_media_stream_t *) h_media;
    memset(media_params, 0, sizeof(ice_media_params_t));

    status = ice_utils_get_local_media_params(media, media_params);

#ifdef DEBUG
    if (status == STUN_OK)
        ice_utils_dump_media_params(media_params);
#endif

    return status;
}


int32_t ice_session_get_media_credentials(handle h_inst, 
        handle h_session, handle h_media, ice_media_credentials_t *cred)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (h_media == NULL) || (cred == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    media = (ice_media_stream_t *) h_media;
    
    stun_memcpy(cred->ice_ufrag, media->local_ufrag, ICE_MAX_UFRAG_LEN);
    stun_memcpy(cred->ice_pwd, media->local_pwd, ICE_MAX_PWD_LEN);

    return STUN_OK;
}


int32_t ice_session_set_media_credentials(handle h_inst, 
        handle h_session, handle h_media, ice_media_credentials_t *cred)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (h_media == NULL) || (cred == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    /** ensure that the given session exists */
    ICE_VALIDATE_SESSION_HANDLE(h_session);

    media = (ice_media_stream_t *) h_media;
    
    stun_memcpy(media->local_ufrag, cred->ice_ufrag, ICE_MAX_UFRAG_LEN);
    stun_memcpy(media->local_pwd, cred->ice_pwd, ICE_MAX_PWD_LEN);

    return STUN_OK;
}


int32_t ice_session_set_peer_session_params(handle h_inst, 
                    handle h_session, ice_session_params_t *session_params)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i, status;

    if ((h_inst == NULL) || (h_session == NULL) || (session_params == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    status = ice_session_fsm_inject_msg(session, 
                                    ICE_REMOTE_PARAMS, session_params, NULL);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, "Processing of remote session params failed");
    }

    return status;
}



int32_t ice_session_set_peer_media_params(handle h_inst, 
        handle h_session, handle h_media, ice_media_params_t *media_params)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i, status;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (h_media == NULL) || (media_params == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    if (session->peer_mode == ICE_INVALID_MODE)
    {
        ICE_LOG (LOG_SEV_ERROR,
            "Peer ICE implementation mode is not yet set - ICE Full/Lite."\
            "Set the same and then try to set the session parameters.");
        return STUN_INVALID_PARAMS;
    }

    media = (ice_media_stream_t *) h_media;
    status = ice_utils_set_peer_media_params(media, media_params);

    return status;
}



int32_t ice_session_set_peer_media_credentials(handle h_inst, 
        handle h_session, handle h_media, ice_media_credentials_t *cred)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || (cred == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    /** ensure that the given session exists */
    ICE_VALIDATE_SESSION_HANDLE(h_session);

    media = (ice_media_stream_t *) h_media;

    stun_memcpy(media->peer_ufrag, cred->ice_ufrag, ICE_MAX_UFRAG_LEN);
    stun_memcpy(media->peer_pwd, cred->ice_pwd, ICE_MAX_PWD_LEN);

    return STUN_OK;
}


int32_t ice_session_set_peer_ice_mode(handle h_inst, 
                    handle h_session, ice_mode_type_t remote_ice_mode)
{
    ice_instance_t *instance;
    ice_session_t *session;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    if ((remote_ice_mode != ICE_MODE_LITE) && 
        (remote_ice_mode != ICE_MODE_FULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);
    
    if (session->peer_mode == remote_ice_mode) return STUN_OK;

    session->peer_mode = remote_ice_mode;

    return STUN_OK;
}



int32_t ice_session_inject_received_msg(handle h_inst, 
                        handle h_session, ice_rx_stun_pkt_t *stun_pkt)
{
    ice_instance_t *instance;
    ice_session_t *session;
    stun_method_type_t method;
    stun_msg_type_t class;
    int32_t i, status;
    ice_session_event_t event;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    if (stun_pkt == NULL)
        return STUN_INVALID_PARAMS;

    if (stun_pkt->h_msg == NULL)
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    status = stun_msg_get_class(stun_pkt->h_msg, &class);
    if (status != STUN_OK)
        return status;

    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    if (status != STUN_OK)
        return status;

    /** TODO - check for class also */
    switch(method)
    {
        case STUN_METHOD_BINDING:
        case STUN_METHOD_ALLOCATE:
        case STUN_METHOD_REFRESH:
        case STUN_METHOD_SEND:
        case STUN_METHOD_DATA:
        case STUN_METHOD_CREATE_PERMISSION:
        case STUN_METHOD_CHANNEL_BIND:
            event = ICE_MSG;
            break;

        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    if (status != STUN_OK) return status;

    return ice_session_fsm_inject_msg(session, event, (handle)stun_pkt, NULL);
}


int32_t ice_session_form_check_lists(handle h_inst, handle h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    return ice_session_fsm_inject_msg(session, ICE_FORM_CHECKLIST, NULL, NULL);
}


int32_t ice_session_start_connectivity_checks(handle h_inst, handle h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    if (session->local_mode == ICE_MODE_LITE)
    {
        ICE_LOG (LOG_SEV_ERROR,
            "Connectivity checks are not performed for ice-lite session");
        return STUN_INVALID_PARAMS;
    }

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    return ice_session_fsm_inject_msg(session, 
                                        ICE_CONN_CHECKS_START, NULL, NULL);
}



int32_t ice_session_inject_timer_event(handle timer_id, handle arg)
{
    int32_t status = STUN_OK;
    ice_timer_params_t *timer;

    if ((timer_id == NULL) || (arg == NULL))
        return STUN_INVALID_PARAMS;

    ICE_LOG (LOG_SEV_DEBUG, 
            "[ICE]: Handling timer id %p and arg %p", timer_id, arg);

    timer = (ice_timer_params_t *) arg;

    /** paranoid check! */
    if (timer->timer_id != timer_id)
    {
        ICE_LOG (LOG_SEV_DEBUG, 
                "[ICE]: stuck with Paranoid check. Timer id in arg %p", 
                timer->timer_id);
        return STUN_INVALID_PARAMS;
    }

    if(timer->type == ICE_TURN_TIMER)
    {
        status = turn_session_inject_timer_message(timer_id, timer->arg);
    }
    else if (timer->type == ICE_CC_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_CC_TIMER");
        status = STUN_INVALID_PARAMS;
    }
    else if (timer->type == ICE_CHECK_LIST_TIMER)
    {
        ice_session_t *session;
        ice_instance_t *instance;

        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_CHECK_LIST_TIMER");
        
        /** find the session for this timer event */
        session = (ice_session_t *) timer->h_session;
        instance = (ice_instance_t *) timer->h_instance;

        status = ice_session_fsm_inject_msg(session, 
                                        ICE_CHECK_LIST_TIMER_EXPIRY, arg, NULL);
    }
    else
    {
        ICE_LOG (LOG_SEV_ERROR, "[ICE]: INVALID timer type");
        status = STUN_INVALID_PARAMS;
    }

    return status;
}



int32_t ice_instance_find_session_for_received_msg(handle h_inst, 
                    handle h_msg, handle transport_param, handle *h_session)
{
    int32_t status;
    ice_instance_t *instance;

    if ((h_inst == NULL) || (h_msg == NULL) || 
            (h_session == NULL) || (transport_param == NULL))
    {
        ICE_LOG(LOG_SEV_ERROR, "Invalid parameter passed when calling "\
                "ice_instance_find_session_for_received_msg() api");
        return STUN_INVALID_PARAMS;
    }

    instance = (ice_instance_t *) h_inst;

    status = ice_utils_find_session_for_transport_handle(
                                        h_inst, transport_param, h_session);
 
    return status;
}


int32_t ice_session_get_session_valid_pairs(handle h_inst, 
            handle h_session, ice_session_valid_pairs_t *valid_pairs)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i, j, status;

    if ((h_inst == NULL) || (h_session == NULL) || (valid_pairs == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    stun_memset(valid_pairs, 0, sizeof(ice_session_valid_pairs_t));

    for (i = 0, j = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        media = session->aps_media_streams[i];
        if(!media) continue;

        if (j >= ICE_MAX_MEDIA_STREAMS) break;

        status = ice_media_utils_get_valid_list(media, 
                                            &valid_pairs->media_list[j]);
        if (status != STUN_OK) break;
        j += 1;
    }

    valid_pairs->num_media = j;

    return status;
}



int32_t ice_session_get_media_valid_pairs(handle h_inst, handle h_session, 
                handle h_media, ice_media_valid_pairs_t *valid_pairs)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || 
            (h_media == NULL) || (valid_pairs == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    stun_memset(valid_pairs, 0, sizeof(ice_media_valid_pairs_t));
    media = (ice_media_stream_t *) h_media;

    return ice_media_utils_get_valid_list(media, valid_pairs);
}



int32_t ice_session_restart_media_stream (handle h_inst,
                                handle h_session, handle h_media)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || (h_media == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    /** inject the event into the session fsm */
    return ice_session_fsm_inject_msg(
                                session, ICE_RESTART, h_media, NULL);
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
