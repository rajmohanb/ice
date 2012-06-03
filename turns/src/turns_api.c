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
#include "turns_api.h"
#include "turns_int.h"
#include "turns_alloc_fsm.h"
#include "turns_utils.h"
#include "turns_table.h"


#define TURN_VALIDATE_SESSION_HANDLE(h_session) { \
    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++) \
        if (instance->ah_session[i] == h_session) { break; } \
\
    if (i == TURN_MAX_CONCURRENT_SESSIONS) { \
        ICE_LOG(LOG_SEV_ERROR, "Invalid TURN session handle"); \
        return STUN_INVALID_PARAMS; \
    } \
} \



int32_t turns_create_instance(handle *h_inst)
{
    turns_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    *h_inst = NULL;

    instance = (turns_instance_t *) 
                        stun_calloc (1, sizeof(turns_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    //stun_memset(instance->ah_session, 0, 
    //                    (sizeof(handle) * TURN_MAX_CONCURRENT_SESSIONS));

    status = turns_create_table(&(instance->h_table));
    if (status != STUN_OK) return status;

    status = stun_txn_create_instance(
                TURN_MAX_CONCURRENT_SESSIONS, &instance->h_txn_inst);
    if (status == STUN_OK)
    {
        *h_inst = (handle) instance;
    }

    return status;
}



int32_t turns_nwk_cb_fxn (handle h_msg, handle h_param)
{
    printf("Please send me out\n");
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



handle turns_start_txn_timer(uint32_t duration, handle arg)
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



int32_t turns_stop_txn_timer(handle timer_id)
{
    int32_t status;
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



int32_t turns_instance_set_osa_callbacks(
                        handle h_inst, turns_osa_callbacks_t *cbs)
{
    turns_instance_t *instance;
    stun_txn_instance_callbacks_t app_cbs;
    int32_t status;

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (turns_instance_t *) h_inst;

    instance->nwk_send_cb = cbs->nwk_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;

    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = turns_nwk_cb_fxn;
    app_cbs.start_timer_cb = turns_start_txn_timer;
    app_cbs.stop_timer_cb = turns_stop_txn_timer;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);

    return status;
}



int32_t turns_instance_set_event_callbacks(
                            handle h_inst, turns_event_callbacks_t *event_cbs)
{
    turns_instance_t *instance;

    if ((h_inst == NULL) || (event_cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((event_cbs->new_alloc_cb == NULL) || 
            (event_cbs->alloc_event_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (turns_instance_t *) h_inst;

    instance->new_alloc_cb = event_cbs->new_alloc_cb;
    instance->alloc_event_cb = event_cbs->alloc_event_cb;

    return STUN_OK;
}



int32_t turns_instance_set_server_software_name(
                    handle h_inst, char *client, uint32_t len)
{
    turns_instance_t *instance;

    if ((h_inst == NULL) || (client == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (turns_instance_t *) h_inst;

    instance->client_name = (u_char *) stun_calloc (1, len);
    if (instance->client_name == NULL) return STUN_MEM_ERROR;

    instance->client_name_len = len;
    stun_memcpy(instance->client_name, (u_char *)client, len);

    return STUN_OK;
}



int32_t turns_instance_set_realm(handle h_inst, char *realm, uint32_t len)
{
    turns_instance_t *instance;

    if ((h_inst == NULL) || (realm == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    instance = (turns_instance_t *) h_inst;

    instance->realm = (char *) stun_calloc (1, len);
    if (instance->realm == NULL) return STUN_MEM_ERROR;

    instance->realm_len = len;
    stun_memcpy(instance->realm, realm, len);

    return STUN_OK;
}



int32_t turns_destroy_instance(handle h_inst)
{
    turns_instance_t *instance;
    uint32_t i;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (turns_instance_t *) h_inst;

    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
    {
        //if (instance->ah_session[i] == NULL) continue;

        //turn_destroy_session(h_inst, instance->ah_session[i]);
    }

    stun_txn_destroy_instance(instance->h_txn_inst);
    
    stun_free(instance->client_name);

    stun_free(instance);

    return STUN_OK;
}



int32_t turns_verify_valid_stun_packet(u_char *pkt, uint32_t pkt_len)
{
    return stun_msg_verify_if_valid_stun_packet(pkt, pkt_len);
}



int32_t turns_inject_received_msg(handle h_inst, turns_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    turns_instance_t *instance = (turns_instance_t *)h_inst;
    turns_allocation_t *alloc_ctxt = NULL;
    stun_method_type_t method;
    stun_msg_type_t msg_type;

    /** 
     * determine the allocation context for this message. In case of TCP, we 
     * could use the socket descriptor to identify the allocation context. 
     * However in case of UDP, the allocation can possibly be identified only 
     * by the 5-tuple. At the server, the 5-tuple value consists of client's 
     * server-reflexive address, the server transport address and the transport 
     * protocol.
     */
    status = turns_table_find_node(instance->h_table, stun_pkt, &alloc_ctxt);

    /** if found, then inject into the allocation fsm */
    if (status == STUN_OK)
    {
        /** TODO: inject into the turns allocation fsm */
        printf("TURN allocation context found.\n");

        status = turns_allocation_fsm_inject_msg(
                            alloc_ctxt, TURNS_ALLOC_REQ, stun_pkt);
        return STUN_OK;
    }

    /** 
     * if not found, and if ALLOCATE request, validate the request and notify
     * the server application about the incoming new allocation request.
     * Subsequently, if the server application approves the allocation, then
     * the new allocation context is created.
     */
    printf("TURN allocation context NOT found.\n");
    
    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    status = stun_msg_get_class(stun_pkt->h_msg, &msg_type);

    if((method == STUN_METHOD_ALLOCATE) && (msg_type == STUN_REQUEST))
    {
        handle h_resp;
        //uint32_t error_code = 0;
        //turns_new_allocation_params_t *params;

        printf("This is a NEW allocate request.\n");

        /** Note/TODO later
         * Right now, the allocation context is being created when the initial
         * request without credential is received. However, this will make
         * our server vulnerable to DDOS kind of attacks where someone can
         * keep pumping-in initial allocate requests without ever authenticating
         * the allocation and thus depleting the server resources. And making
         * the server to be unusable even for genuine allocation requests from
         * user. Typically we should
         * - do not club the alloc pool for these initial requests  with the
         *   approved pool of allocations.
         * - in addition to separartion of pools, there should be a limit for
         *   the number of of unapproved/authenticated allocation contexts.
         */

        /** create a new allocation context */
        alloc_ctxt = turns_utils_create_allocation_context(instance, stun_pkt);
        if (alloc_ctxt == NULL)
        {
            printf("Creation of new allocation context failed: [%d]\n", status);
            return STUN_MEM_ERROR;
        }

        /** add the new allocation to the table/pool */
        status = turns_table_add_node(instance->h_table, alloc_ctxt);
        if (status != STUN_OK) return status;

        /** 
         * For any new allocation, the server needs to challenge the request.
         * And in the 401 challenge reponse, the server generates a new
         * nonce string and adds a realm and sends back to the client. The 
         * client must re-send the allocate request but this time the request 
         * must include the authentication parameters and message-integrity 
         * as per long-term credential mechanism.
         *
         * Note:
         * Right now we generate a 401 even if the allocate request contains
         * long-term credential related attributes like username, realm and
         * nonce because these are not the valid values for the server.
         *
         * TODO
         * Now that we have created an allocation context even when sending
         * a 401 challenge, then what if we never receive any response OR 
         * the client never successfully authenticates? This can be a 
         * security issue or DDOS stuff? Probably we must time out the 
         * allocation by having some timer so that resources do not get
         * held up perpetually.
         */

#if 0
        params = (turns_new_allocation_params_t *) 
                stun_calloc (1, sizeof(turns_new_allocation_params_t));
        if (params == NULL) return STUN_MEM_ERROR;

        status = turns_utils_extract_info_from_alloc_request(
                                        stun_pkt->h_msg, params, &error_code);
        if(status != STUN_OK)
        {
            if (error_code > 0)
            {
#endif
#if 0
                handle h_txn;

                status = stun_create_txn(instance->h_txn_inst,
                            STUN_SERVER_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
                if (status != STUN_OK) return status; // TODO - destroy the msg?

                status = stun_txn_set_app_param(
                                    h_txn_inst, h_txn, (handle)session);
                if (status != STUN_OK) return status; // TODO graceful exit? remove txn?

                status = stun_txn_inject_received_msg(
                                instance->h_txn_inst, h_txn, stun_pkt->h_msg);
                if (status != STUN_OK) return status; // TODO remove txn? graceful exit?
#endif

                status = turns_utils_create_error_response(
                        alloc_ctxt, stun_pkt->h_msg, 401, &h_resp);
                // TODO check status? remove txn? graceful exit?
                if(status != STUN_OK) return status;

                /** send the response directly, not using the txn module */
                instance->nwk_send_cb(h_resp, 
                        stun_pkt->src.host_type, stun_pkt->src.ip_addr, 
                        stun_pkt->src.port, stun_pkt->transport_param, NULL);

                printf("turns: sent error response with error code: 401\n");
                
                alloc_ctxt->state = TSALLOC_CHALLENGED;
#if 0
            }

            stun_free(params);
            return status;
        }

        status = turns_utils_notify_new_alloc_request_to_app(instance, params);
        if(status != STUN_OK)
        {
            stun_free(params);
            return status;
        }
#endif
    }
    else
    {
        printf("Ignoring a stray STUN/TURN message\n");
    }
    
    return status;
}



int32_t turns_inject_timer_event(
                    handle timer_id, handle arg, handle *ice_session)
{
    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
