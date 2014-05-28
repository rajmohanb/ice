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
#include "stuns_api.h"
#include "stuns_int.h"
#include "stuns_utils.h"
//#include "stuns_table.h"



#define TURN_VALIDATE_SESSION_HANDLE(h_session) { \
    for (i = 0; i < STUNS_MAX_CONCURRENT_SESSIONS; i++) \
        if (instance->ah_session[i] == h_session) { break; } \
\
    if (i == STUNS_MAX_CONCURRENT_SESSIONS) { \
        ICE_LOG(LOG_SEV_ERROR, "Invalid TURN session handle"); \
        return STUN_INVALID_PARAMS; \
    } \
} \



int32_t stuns_create_instance(handle *h_inst)
{
    stuns_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    *h_inst = NULL;

    instance = (stuns_instance_t *) 
                        stun_calloc (1, sizeof(stuns_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    //stun_memset(instance->ah_session, 0, 
    //                    (sizeof(handle) * STUNS_MAX_CONCURRENT_SESSIONS));

    //status = turns_create_table(&(instance->h_table));
    //if (status != STUN_OK) return status;

    /** TODO - need to eliminate STUNS_MAX_CONCURRENT_SESSIONS */ 
    status = stun_txn_create_instance(
                STUNS_MAX_CONCURRENT_SESSIONS, &instance->h_txn_inst);
    if (status == STUN_OK)
    {
        *h_inst = (handle) instance;
    }

    return status;
}



int32_t stuns_nwk_cb_fxn (handle h_msg, handle h_param)
{
    ICE_LOG(LOG_SEV_DEBUG, "Please send me out");
    //turn_session_t *session = (turn_session_t *) h_param;

    /** turn client always talks to the turn/stun server */

    /* TODO - what about when sending rtp data? */

#if 0
    return session->instance->nwk_send_cb(h_msg, 
                    session->cfg.server.host_type,
                    session->cfg.server.ip_addr,
                    session->cfg.server.port, 
                    session->transport_param,
                    session->app_param);
#endif

    return STUN_OK;
}



handle stuns_start_txn_timer(uint32_t duration, handle arg)
{
#if 0
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
#endif
    return 0;
}



int32_t stuns_stop_txn_timer(handle timer_id)
{
    int32_t status = STUN_OK;
#if 0
    turn_timer_params_t *timer = (turn_timer_params_t *) timer_id;
    turn_session_t *session;

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
#endif

    return status;
}



int32_t stuns_instance_set_osa_callbacks(
                        handle h_inst, stuns_osa_callbacks_t *cbs)
{
    stuns_instance_t *instance;
    stun_txn_instance_callbacks_t app_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (stuns_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;

    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = stuns_nwk_cb_fxn;
    app_cbs.start_timer_cb = stuns_start_txn_timer;
    app_cbs.stop_timer_cb = stuns_stop_txn_timer;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);

    return status;
}



int32_t stuns_instance_set_server_software_name(
                    handle h_inst, char *client, uint32_t len)
{
    stuns_instance_t *instance;

    if ((h_inst == NULL) || (client == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (stuns_instance_t *) h_inst;

    instance->client_name = (u_char *) stun_calloc (1, len);
    if (instance->client_name == NULL) return STUN_MEM_ERROR;

    instance->client_name_len = len;
    stun_memcpy(instance->client_name, (u_char *)client, len);

    return STUN_OK;
}



int32_t stuns_destroy_instance(handle h_inst)
{
    stuns_instance_t *instance;
    uint32_t i;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (stuns_instance_t *) h_inst;

    for (i = 0; i < STUNS_MAX_CONCURRENT_SESSIONS; i++)
    {
        //if (instance->ah_session[i] == NULL) continue;

        //turn_destroy_session(h_inst, instance->ah_session[i]);
    }

    stun_txn_destroy_instance(instance->h_txn_inst);
    
    stun_free(instance->client_name);

    stun_free(instance);

    return STUN_OK;
}



int32_t stuns_verify_valid_stun_packet(u_char *pkt, uint32_t pkt_len)
{
    return stun_msg_verify_if_valid_stun_packet(pkt, pkt_len);
}



int32_t stuns_inject_received_msg(handle h_inst, stuns_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    stun_method_type_t method;
    stun_msg_type_t msg_type;
    stuns_instance_t *instance = (stuns_instance_t *)h_inst;

    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    status = stun_msg_get_class(stun_pkt->h_msg, &msg_type);

    if((method != STUN_METHOD_BINDING) || (msg_type != STUN_REQUEST))
    {
        ICE_LOG(LOG_SEV_INFO, "STUNS: Ignoring the stray mesage");
        return STUN_INVALID_PARAMS;
    }

    /** process the stun request */
    status = stuns_utils_process_stun_binding_request(instance, stun_pkt);

    return status;
}



int32_t stuns_inject_timer_event(
                    handle timer_id, handle arg, handle *ice_session)
{
    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
