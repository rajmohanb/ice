/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2014, MindBricks Technologies               *
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
#include "stun_enc_dec_api.h"
#include "conn_check_api.h"
#include "turn_api.h"
#include "stun_binding_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_session_fsm.h"
#include "ice_utils.h"



#define ICE_VALIDATE_SESSION_HANDLE(h_session) { \
    for (i = 0; i < ICE_MAX_CONCURRENT_SESSIONS; i++) \
        if (instance->aps_sessions[i] == h_session) { break; } \
\
    if (i == ICE_MAX_CONCURRENT_SESSIONS) { \
        ICE_LOG(LOG_SEV_ERROR, "[ICE] Invalid session handle"); \
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

    status = stun_binding_create_instance(&instance->h_bind_inst);
    if (status != STUN_OK)
    {
        turn_destroy_instance(instance->h_turn_inst);
        stun_free(instance);
        return status;
    }

    status = conn_check_create_instance(&instance->h_cc_inst);
    if (status != STUN_OK)
    {
        turn_destroy_instance(instance->h_turn_inst);
        stun_binding_destroy_instance(instance->h_bind_inst);
        stun_free(instance);
        return status;
    }

    instance->nomination_mode = ICE_DEFAULT_NOMINATION_TYPE;

    *h_inst = (handle) instance;

    return status;
}


static void ice_turn_callback_fxn (handle h_turn_inst, 
        handle h_turn_session, turn_session_state_t turn_session_state)
{
    int32_t status;
    ice_media_stream_t *media;
    ice_session_event_t event;
    ice_int_params_t event_params= {0};

    if ((h_turn_inst == NULL) || (h_turn_session == NULL))
    {
        ICE_LOG(LOG_SEV_ERROR, "[ICE] Invalid parameters received in turn "\
                "callback routine. Null turn instance/session handle");
        return;
    }

    ICE_LOG(LOG_SEV_DEBUG, "[ICE] TURN session state changed to %s for "\
            "turn session %p", turn_states[turn_session_state], h_turn_session);

    /** get the ice session handle who owns this turn session */
    status = turn_session_get_app_param(
                        h_turn_inst, h_turn_session, (handle *)&media);

    switch(turn_session_state)
    {
        case TURN_OG_ALLOCATED:
            event = ICE_GATHERED_CANDS;
            break;

        case TURN_OG_FAILED:
            event = ICE_GATHER_FAILED;
            break;

        case TURN_IDLE:
        {
            /**
             * This needs to be injected into ice session fsm? 
             * For now, clear the turn session here itself...
             */
            ice_media_utils_clear_turn_session(media, 
                                        h_turn_inst, h_turn_session);

            event = ICE_SES_EVENT_MAX;
        }
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
            "[ICE] Ignoring turn session state %d", turn_session_state);
        return;
    }

    event_params.h_inst = h_turn_inst;
    event_params.h_session = h_turn_session;


    status = ice_session_fsm_inject_msg(
                    media->ice_session, event, &event_params, NULL);

    return;
}



static void ice_cc_callback_fxn (handle h_cc_inst, 
        handle h_cc_session, conn_check_session_state_t state, handle data)
{
    int32_t status;
    ice_session_event_t event;
    handle h_session;
    ice_session_t *session;

    if ((h_cc_inst == NULL) || (h_cc_session == NULL))
    {
        ICE_LOG (LOG_SEV_ERROR, "[ICE] FIXME: parameters not valid");
        return;
    }

    switch(state)
    {
        case CC_OG_IDLE:
        case CC_OG_CHECKING:
            break;

        case CC_OG_TERMINATED:
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "[ICE] Outgoing connectivity check terminated");

            /** declare success now? check if it is success */
            event = ICE_CONN_CHECKS_DONE;
        }
        break;

        case CC_IC_IDLE:
        break;

        case CC_IC_TERMINATED:
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "****************************************************\n\n");
            ICE_LOG (LOG_SEV_DEBUG,
                    "[ICE] Incoming connectivity check terminated");
            ICE_LOG (LOG_SEV_DEBUG, 
                    "\n\n************************************************\n\n");

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



static handle ice_turn_start_timer(uint32_t duration, handle arg)
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



static handle ice_stun_bind_start_timer(uint32_t duration, handle arg)
{
    int32_t status;
    ice_timer_params_t *timer;
    handle h_bind_session, h_bind_inst;
    ice_media_stream_t *media;

    timer = (ice_timer_params_t *) 
        stun_calloc (1, sizeof(ice_timer_params_t));
    if (timer == NULL) return 0;

    status = turn_session_timer_get_session_handle(
                                        arg, &h_bind_session, &h_bind_inst);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    status = stun_binding_session_get_app_param( 
                            h_bind_inst, h_bind_session, (handle *)&media);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    timer->h_instance = media->ice_session->instance;
    timer->h_session = media->ice_session;
    timer->arg = arg;
    timer->type = ICE_BIND_TIMER;

    timer->timer_id = 
        media->ice_session->instance->start_timer_cb(duration, timer);
    if (timer->timer_id)
        return timer;

ERROR_EXIT_PT:
    stun_free(timer);
    return 0;
}



static handle ice_cc_start_timer(uint32_t duration, handle arg)
{
    int32_t status;
    ice_timer_params_t *timer;
    handle h_cc_session, h_cc_inst;
    ice_cand_pair_t *cp;

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
                            h_cc_inst, h_cc_session, (handle *)&cp);
    if (status != STUN_OK)
    {
        goto ERROR_EXIT;
    }

    timer->h_instance = cp->media->ice_session->instance;
    timer->h_session = cp->media->ice_session;
    timer->h_media = cp->media;
    timer->arg = arg;
    timer->type = ICE_CC_TIMER;

    timer->timer_id = 
        cp->media->ice_session->instance->start_timer_cb(duration, timer);
    if (timer->timer_id)
    {
        return timer;
    }
    
ERROR_EXIT:
    stun_free(timer);
    return 0;
}


static int32_t ice_stop_timer(handle timer_id)
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


static int32_t ice_encode_and_send_message(handle h_msg, 
                stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                uint32_t port, handle transport_param, handle app_param)
{
    u_char *buf;
    uint32_t sent_bytes, buf_len, status;
    int32_t sock_fd = (int32_t) transport_param;
    ice_media_stream_t *media = (ice_media_stream_t *) app_param;
    ice_session_t *ice_session;
    stun_auth_params_t auth = {0};
    stun_method_type_t method;

    if ((h_msg == NULL) || (ip_addr == NULL) || 
                            (port == 0) || (transport_param == NULL))
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] Invalid parameter, hence not sending message");
        return STUN_INVALID_PARAMS;
    }

    if (!app_param) return STUN_INT_ERROR;

    ice_session = media->ice_session;

    /** authentication parameters for message integrity */
    status = stun_msg_get_method(h_msg, &method);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] Invalid message!! unable to retrieve STUN method type");
        return STUN_INVALID_PARAMS;
    }

    if (method == STUN_METHOD_BINDING)
    {
        stun_msg_type_t msg_class;

        /** connectivity check mesages - short term credential */
        status = stun_msg_get_class(h_msg, &msg_class);
        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "[ICE] Invalid message!! unable to retrieve STUN msg class");
            return STUN_INVALID_PARAMS;
        }

        if (msg_class == STUN_REQUEST)
        {
            auth.key_len = stun_strlen(media->peer_pwd);
            if(auth.key_len > STUN_MSG_AUTH_PASSWORD_LEN)
                auth.key_len = STUN_MSG_AUTH_PASSWORD_LEN;
            stun_strncpy((char *)auth.key, media->peer_pwd, auth.key_len);
        }
        else if ((msg_class == STUN_SUCCESS_RESP) || 
                 (msg_class == STUN_ERROR_RESP))
        {
            auth.key_len = stun_strlen(media->local_pwd);
            if(auth.key_len > STUN_MSG_AUTH_PASSWORD_LEN)
                auth.key_len = STUN_MSG_AUTH_PASSWORD_LEN;
            stun_strncpy((char *)auth.key, media->local_pwd, auth.key_len);
        }
        
        /** Indications are not authenticated */
    }
    else
    {
        /** turn message - calculate the long-term authentication hmac key */
        auth.key_len = STUN_MSG_AUTH_PASSWORD_LEN;
        status = ice_utils_compute_turn_hmac_key(
                            ice_session, auth.key, &auth.key_len);

        if (status != STUN_OK) return status;
    }

    buf = (u_char *) stun_calloc(1, TRANSPORT_MTU_SIZE);
    buf_len = TRANSPORT_MTU_SIZE;

    status = stun_msg_encode(h_msg, &auth, buf, &buf_len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] stun_msg_format() returned error %d", status);
        stun_free(buf);
        return STUN_INT_ERROR;
    }

    if (!sock_fd)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] some error! transport socket handle is NULL");
        stun_free(buf);
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



static int32_t ice_encode_and_send_stun_binding_message(handle h_msg, 
        stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, uint32_t port, 
        handle transport_param, handle app_param, bool_t msg_intg_reqd)
{
    u_char *buf;
    uint32_t sent_bytes, buf_len;
    int32_t status, sock_fd = (int32_t) transport_param;
    ice_cand_pair_t *cp = (ice_cand_pair_t *) app_param;
    ice_media_stream_t *media;
    ice_session_t *ice_session;
    stun_auth_params_t auth = {0};
    stun_msg_type_t msg_class;

    if ((h_msg == NULL) || (ip_addr == NULL) || 
                            (port == 0) || (transport_param == NULL))
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] Invalid parameter, hence not sending message");
        return STUN_INVALID_PARAMS;
    }

    if (!app_param) return STUN_INT_ERROR;

    if (msg_intg_reqd == true)
    {
        /** connectivity check mesages - short term credential */
        status = stun_msg_get_class(h_msg, &msg_class);
        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "[ICE] Invalid message!! unable to retrieve STUN msg class");
            return STUN_INVALID_PARAMS;
        }

        if (msg_class == STUN_REQUEST)
        {
            cp = (ice_cand_pair_t *) app_param;
            media = cp->media;
            ice_session = media->ice_session;

            auth.key_len = stun_strlen(media->peer_pwd);
            if(auth.key_len > STUN_MSG_AUTH_PASSWORD_LEN)
                auth.key_len = STUN_MSG_AUTH_PASSWORD_LEN;
            stun_strncpy((char *)auth.key, media->peer_pwd, auth.key_len);
        }
        else if ((msg_class == STUN_SUCCESS_RESP) || 
                 (msg_class == STUN_ERROR_RESP))
        {
            media = (ice_media_stream_t *) app_param;
            ice_session = media->ice_session;
            cp = NULL;

            auth.key_len = stun_strlen(media->local_pwd);
            if(auth.key_len > STUN_MSG_AUTH_PASSWORD_LEN)
                auth.key_len = STUN_MSG_AUTH_PASSWORD_LEN;
            stun_strncpy((char *)auth.key, media->local_pwd, auth.key_len);
        }
            
        /** Indications are not authenticated */
    }
    else
    {
        media = (ice_media_stream_t *) app_param;
        ice_session = media->ice_session;
    }

    buf = (u_char *) stun_calloc(1, TRANSPORT_MTU_SIZE);
    buf_len = TRANSPORT_MTU_SIZE;

    status = stun_msg_encode(h_msg, &auth, buf, &buf_len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] stun_msg_format() returned error %d", status);
        stun_free(buf);
        return STUN_INT_ERROR;
    }

    if (!sock_fd)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] some error! transport socket handle is NULL");
        stun_free(buf);
        return STUN_INVALID_PARAMS;
    }

    /** 
     * connectivity check messages that are sent using the relayed 
     * candidate must be encoded in a TURN DATA indication message
     */
    if((msg_intg_reqd == true) && (msg_class == STUN_REQUEST) && 
       (cp->local->type == ICE_CAND_TYPE_RELAYED))
    {
        handle h_turn_session;
        stun_inet_addr_t dest = {0};
        handle h_turn_inst = cp->media->ice_session->instance->h_turn_inst;

        /** better way to identify turn session? */
        h_turn_session = cp->media->h_turn_sessions[cp->local->comp_id - 1];

        dest.host_type = ip_addr_type;
        dest.port = port;
        stun_memcpy(dest.ip_addr, ip_addr, ICE_IP_ADDR_MAX_LEN);

        status = turn_session_send_application_data(h_turn_inst, 
                                        h_turn_session, &dest, buf, buf_len);
    }
    else
    {
        sent_bytes = ice_session->instance->nwk_send_cb(buf, 
                buf_len, ip_addr_type, ip_addr, port, transport_param);

        if (sent_bytes == -1)
            status = STUN_INT_ERROR;
        else
            status = STUN_OK;
    }

    stun_free(buf);

    return status;
}



static int32_t ice_encode_and_send_stun_bind_message (
        handle h_msg, stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
        uint32_t port, handle transport_param, handle app_param)
{
    return ice_encode_and_send_stun_binding_message(h_msg, 
            ip_addr_type, ip_addr, port, transport_param, app_param, false);
}



static int32_t ice_encode_and_send_conn_check_message(handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, handle app_param)
{
    return ice_encode_and_send_stun_binding_message(h_msg, 
            ip_addr_type, ip_addr, port, transport_param, app_param, true);
}



void ice_handle_app_data(handle h_turn_inst, 
                    handle h_turn_session, void *data, uint32_t data_len, 
                    stun_inet_addr_t *src, handle transport_param)
{
    int32_t status;
    ice_media_stream_t *media;
    stun_method_type_t method;
    handle h_msg;
    ice_rx_stun_pkt_t pkt;

    status = turn_session_get_app_param(h_turn_inst, 
                                    h_turn_session, (handle) &media);
    if (status != STUN_OK) return;

    /** check if this is a STUN message */
    status = stun_msg_verify_if_valid_stun_packet(data, data_len);
    if (status == STUN_MSG_NOT)
    {
        ice_candidate_t *cand = NULL;
        ice_instance_t *inst = (ice_instance_t *) media->ice_session->instance;

        cand = ice_utils_get_local_cand_for_transport_param(
                                            media, transport_param, false);

        if (cand == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE] Could not locate component ID for received "\
                    "application data. Discarding ....\n");
            return;
        }

        /** This is application protocol data, pass it on to app */
        inst->rx_app_data_cb(inst, 
                media->ice_session, media, cand->comp_id, data, data_len);
        return;
    }

    /*
     * so, this is a stun message. Determine the media and ice session for 
     * turn session.  decode the message. if the method type is BINDING, 
     * then determine the conn check session and inject the message into 
     * the conn check session.
     */
    status = stun_msg_decode(data, data_len, true, &h_msg);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "[ICE] Decoding of STUN message received via TURN failed [%d]",
                status);
        return;
    }

    status = stun_msg_get_method(h_msg, &method);
    if (status != STUN_OK) return;

    if (method != STUN_METHOD_BINDING)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "[ICE] The method of the decoded message received via "\
                "TURN module DATA indication is %d. Hence discarding "\
                "the message.", method);
        return;
    }

    pkt.h_msg = h_msg;
    pkt.transport_param = transport_param;
    stun_memcpy(&pkt.src, src, sizeof(stun_inet_addr_t));
    pkt.relayed_check = true;

    ice_session_fsm_inject_msg(media->ice_session, ICE_MSG, (handle)&pkt, NULL);

    return;
}


int32_t ice_instance_set_callbacks(handle h_inst, 
                                        ice_instance_callbacks_t *cbs)
{
    ice_instance_t *instance;
    conn_check_instance_callbacks_t cc_cbs;
    turn_instance_callbacks_t turn_cbs;
    stun_binding_instance_callbacks_t bind_cbs;
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
    instance->rx_app_data_cb = cbs->app_data_cb;
    
    /** set callbacks to turn module */
    turn_cbs.nwk_cb = ice_encode_and_send_message;
    turn_cbs.rx_data_cb = ice_handle_app_data;

    turn_cbs.start_timer_cb = ice_turn_start_timer;
    turn_cbs.stop_timer_cb = ice_stop_timer;

    /** set callback function for turn session state */
    turn_cbs.session_state_cb = ice_turn_callback_fxn;

    status = turn_instance_set_callbacks(instance->h_turn_inst, &turn_cbs);
    if (status != STUN_OK)
    {
        return status;
    }
    
    /** set callbacks to stun binding module */
    bind_cbs.nwk_cb = ice_encode_and_send_stun_bind_message;
    bind_cbs.start_timer_cb = ice_stun_bind_start_timer;
    bind_cbs.stop_timer_cb = ice_stop_timer;

    status = stun_binding_instance_set_callbacks(
                                instance->h_bind_inst, &bind_cbs);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "stun_binding_instance_set_callbacks() returned error: %d\n", 
                status);
        return status;
    }

    /** set callbacks to connectivity check module */
    cc_cbs.nwk_cb = ice_encode_and_send_conn_check_message;
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
    instance->trickle_cand_cb = event_handlers->trickle_cand_cb;
    
    return STUN_OK;
}



int32_t ice_instance_set_client_software_name(handle h_inst, 
                                                u_char *client, uint32_t len)
{
    ice_instance_t *instance;
    int32_t status = STUN_OK;

    if ((h_inst == NULL) || (client == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    instance->client_name = (u_char *) stun_calloc (1, len);
    if (instance->client_name == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE] Memory allocation failed for ICE instance client name");
        return STUN_MEM_ERROR;
    }

    stun_memcpy(instance->client_name, client, len);
    instance->client_name_len = len;

    status = turn_instance_set_client_software_name(
                                        instance->h_turn_inst, client, len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    status = conn_check_instance_set_client_software_name(
                                        instance->h_cc_inst, client, len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    return status;

ERROR_EXIT_PT:

    stun_free(instance->client_name);

    return status;
}



int32_t ice_instance_set_connectivity_check_nomination_mode(
                                handle h_inst, ice_nomination_type_t nom_type)
{
    ice_instance_t *instance;

    if (h_inst == NULL) return STUN_INVALID_PARAMS;

    if ((nom_type != ICE_NOMINATION_TYPE_REGULAR) && 
        (nom_type != ICE_NOMINATION_TYPE_AGGRESSIVE))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;

    instance->nomination_mode = nom_type;

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
    turn_destroy_instance(instance->h_turn_inst);
    stun_binding_destroy_instance(instance->h_bind_inst);

    stun_free(instance->client_name);

    stun_free(instance);

    return STUN_OK;
}


int32_t ice_create_session(
            handle h_inst, ice_session_type_t ice_sess_type, 
            ice_mode_type_t mode, handle app_handle, handle *h_session)
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

    /** select a random number as tie-breaker */
    session->tie_breaker = platform_64bit_random_number();

    session->state = ICE_SES_IDLE;
    session->peer_mode = ICE_INVALID_MODE;
    session->o_destroyed = false;

    session->app_handle = app_handle;

    *h_session = session;

    ICE_LOG(LOG_SEV_DEBUG, "[ICE] ICE session created successfully with "\
            "Agent role [%d] mode [%d]", session->role, session->local_mode);

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

    return STUN_OK;
}



int32_t ice_destroy_session(handle h_inst, handle h_session)
{
    ice_instance_t *instance;
    ice_session_t *session;
    uint32_t i, j, count = 0;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    session->o_destroyed = true;

    /** clean up media */
    for (j = 0; j < ICE_MAX_MEDIA_STREAMS; j++)
    {
        if (session->aps_media_streams[j])
        {
            ice_session_remove_media_stream(h_inst, 
                            h_session, session->aps_media_streams[j]);
            count++;
        }
    }

    if (session->use_relay == false)
    {
        instance->aps_sessions[i] = NULL;
        stun_free(session);
    }
    else
    {
        if (count == 0)
        {
            instance->aps_sessions[i] = NULL;
            stun_free(session);
        }
    }

    return STUN_OK;
}


int32_t ice_session_add_media_stream (handle h_inst, handle h_session, 
                        ice_api_media_stream_t *media_params, handle *h_media)
{
    int32_t i, status;
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *m;

    if ((h_inst == NULL) || (h_session == NULL) || (media_params == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    if (session->num_media_streams >= ICE_MAX_MEDIA_STREAMS)
    {
        ICE_LOG(LOG_SEV_ERROR, "[ICE] Adding of media stream failed. "\
               "Maximum allowed media streams per session already reached.");
        return STUN_NO_RESOURCE;
    }

    status = ice_utils_add_new_media_stream(session, media_params, &m);
    if (status != STUN_OK) {
        ICE_LOG(LOG_SEV_ERROR, "[ICE] Adding of media stream failed.");
        return status;
    }

    /* Notify the ice user about the host candidate(s) */
    for (i = 0; i < media_params->num_comp; i++)
    {
        status = ice_session_utils_notify_ice_candidate_event(
                m, ICE_CAND_TYPE_HOST, media_params->host_cands[i].comp_id);
        if (status != STUN_OK) {
            ICE_LOG(LOG_SEV_ERROR, 
                    "[ICE] Notifying user about the host candidate failed.");
            /* continue? */
        }
    }

    /* 
     * TODO; do we inject into the session fsm? any 
     * change required in the session fsm? any change in 
     * the state machine of the newly created media stream? 
     */

    *h_media = m;

    return status;
    //return ice_session_fsm_inject_msg(session, ICE_ADD_MEDIA, media, h_media);
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


int32_t ice_session_gather_candidates(handle h_inst, 
                                        handle h_session, bool_t use_relay)
{
    ice_instance_t *instance;
    ice_session_t *session;
    int32_t i;

    if ((h_inst == NULL) || (h_session == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    if ((use_relay == true) && (session->turn_cfg.server.port == 0))
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] TURN/Relay server configuration not done for "\
                "the session.");
        return STUN_INVALID_PARAMS;
    }

    if ((use_relay == false) && (session->stun_cfg.server.port == 0))
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] STUN server configuration not done for the session.");
        return STUN_INVALID_PARAMS;
    }

    session->use_relay = use_relay;

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
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] Processing of remote session params failed");
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
            "[ICE] Peer ICE implementation mode is not yet set - ICE Full/Lite"\
            " Set the same and then try to set the session parameters.");
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


int32_t ice_session_set_peer_trickle_candidate(handle h_inst, 
            handle h_session, handle h_media, ice_cand_t *peer_cand)
{
    int32_t i, status;
    ice_instance_t *instance;
    ice_session_t *session;

    if ((h_inst == NULL) || (h_session == NULL) 
            || (h_media == NULL) || (peer_cand == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    /* TODO; validate media handle? */

    status = ice_session_fsm_inject_msg(
                session, ICE_TRICKLE_CAND, peer_cand, h_media);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE] Processing of remote trickle ice candidate failed");
    }

    return status;
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

    if ((h_inst == NULL) || (h_session == NULL)) return STUN_INVALID_PARAMS;

    if (stun_pkt == NULL) return STUN_INVALID_PARAMS;

    if (stun_pkt->h_msg == NULL) return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    status = stun_msg_get_class(stun_pkt->h_msg, &class);
    if (status != STUN_OK)
        return status;

    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    if (status != STUN_OK)
        return status;

    /** need to check for class also? */
    switch(method)
    {
        case STUN_METHOD_BINDING:
        case STUN_METHOD_ALLOCATE:
        case STUN_METHOD_REFRESH:
        case STUN_METHOD_DATA:
        case STUN_METHOD_CREATE_PERMISSION:
        case STUN_METHOD_CHANNEL_BIND:
            event = ICE_MSG;
            break;

        case STUN_METHOD_SEND:
            status = STUN_INVALID_PARAMS;
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE] Received SEND message are ignored");
            break;

        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    if (status != STUN_OK) return status;

    stun_pkt->relayed_check = false;

    ICE_LOG (LOG_SEV_DEBUG,
        "[ICE] Received ICE msg on socket %d", (int)stun_pkt->transport_param);

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
            "[ICE] Connectivity checks are not performed for ice-lite session");
        return STUN_INVALID_PARAMS;
    }

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    return ice_session_fsm_inject_msg(session, 
                                        ICE_CONN_CHECKS_START, NULL, NULL);
}



int32_t ice_session_inject_timer_event(
                    handle timer_id, handle arg, handle *ice_session)
{
    int32_t i, status = STUN_OK;
    ice_timer_params_t *timer;
    ice_instance_t *instance;
    ice_session_t *session;

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

    instance = timer->h_instance;
    ICE_VALIDATE_SESSION_HANDLE(timer->h_session);

    session = (ice_session_t *) timer->h_session;
    *ice_session = session;

    if(timer->type == ICE_TURN_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_TURN_TIMER");
        status = turn_session_inject_timer_message(timer_id, timer->arg);

        stun_free(timer);
    }
    else if (timer->type == ICE_CC_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_CC_TIMER");

        /** conn check timer event has to be fed thru the resp media fsm */
        status = ice_session_fsm_inject_msg(session, 
                                        ICE_CONN_CHECK_TIMER, arg, NULL);

        stun_free(timer);
    }
    else if (timer->type == ICE_CHECK_LIST_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_CHECK_LIST_TIMER");
        
        status = ice_session_fsm_inject_msg(session, 
                                        ICE_CHECK_LIST_TIMER_EXPIRY, arg, NULL);
        if (status == STUN_INVALID_PARAMS) stun_free(timer);
    }
    else if (timer->type == ICE_NOMINATION_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_NOMINATION_TIMER");
        
        status = ice_session_fsm_inject_msg(session, 
                                        ICE_NOMINATION_TIMER_EXPIRY, arg, NULL);
        if (status == STUN_INVALID_PARAMS) stun_free(timer);
    }
    else if (timer->type == ICE_BIND_TIMER)
    {
        handle h_bind_session;
        ice_int_params_t event_params= {0};

        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_BIND_TIMER");
        status = stun_binding_session_inject_timer_event(
                                timer_id, timer->arg, &h_bind_session);

        if (status == STUN_TERMINATED)
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "[ICE]: STUN BINDING session terminated due to timeout. "\
                    "Gathering of candidates failed");

            event_params.h_inst = session->instance->h_turn_inst;
            event_params.h_session = h_bind_session;

            /** if the gathering failed, let the ice media know of it */
            status = ice_session_fsm_inject_msg(session, 
                                ICE_GATHER_FAILED, &event_params, NULL);
        }

        stun_free(timer);
    }
    else if (timer->type == ICE_KEEP_ALIVE_TIMER)
    {
        ICE_LOG (LOG_SEV_DEBUG, "[ICE]: Fired timer type ICE_KEEP_ALIVE_TIMER");
        
        status = ice_session_fsm_inject_msg(session, 
                                        ICE_KEEP_ALIVE_EXPIRY, arg, NULL);
        if (status == STUN_INVALID_PARAMS) stun_free(timer);
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
        ICE_LOG(LOG_SEV_ERROR, "[ICE] Invalid parameter passed when calling "\
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



int32_t ice_session_get_nominated_pairs(handle h_inst, 
            handle h_session, ice_session_valid_pairs_t *nom_pairs)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_stream_t *media;
    int32_t i, j, status;

    if ((h_inst == NULL) || (h_session == NULL) || (nom_pairs == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    stun_memset(nom_pairs, 0, sizeof(ice_session_valid_pairs_t));

    for (i = 0, j = 0; i < ICE_MAX_MEDIA_STREAMS; i++)
    {
        media = session->aps_media_streams[i];
        if(!media) continue;

        if (j >= ICE_MAX_MEDIA_STREAMS) break;

        status = ice_media_utils_get_nominated_list(media, 
                                            &nom_pairs->media_list[j]);
        if (status != STUN_OK) break;
        j += 1;
    }

    nom_pairs->num_media = j;

    return status;
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



int32_t ice_session_send_media_data (handle h_inst, handle h_session, 
                handle h_media, uint32_t comp_id, u_char *data, uint32_t len)
{
    ice_instance_t *instance;
    ice_session_t *session;
    ice_media_data_t media_data;
    uint32_t i;

    if ((h_inst == NULL) || (h_session == NULL) || (h_media == NULL))
        return STUN_INVALID_PARAMS;

    instance = (ice_instance_t *) h_inst;
    session = (ice_session_t *) h_session;

    ICE_VALIDATE_SESSION_HANDLE(h_session);

    media_data.h_media = h_media;
    media_data.comp_id = comp_id;
    media_data.data = data;
    media_data.len = len;

    /** inject the event into the session fsm */
    return ice_session_fsm_inject_msg(session, 
                            ICE_SEND_MEDIA_DATA, &media_data, NULL);
}



int32_t ice_instance_verify_valid_stun_packet(u_char *pkt, uint32_t pkt_len)
{
    return stun_msg_verify_if_valid_stun_packet(pkt, pkt_len);
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
