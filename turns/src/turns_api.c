/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2013, MindBricks Technologies               *
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

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/mman.h>

#include "stun_base.h"
#include "msg_layer_api.h"
#ifndef MB_STATELESS_TURN_SERVER
#include "stun_txn_api.h"
#endif
#include "turns_api.h"
#include "turns_int.h"
#include "turns_alloc_fsm.h"
#include "turns_utils.h"
#include "turns_table.h"



int32_t turns_create_instance(uint32_t max_allocs, handle *h_inst)
{
    turns_instance_t *instance;
    int32_t status;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    *h_inst = NULL;

    instance = (turns_instance_t *) 
                        stun_calloc (1, sizeof(turns_instance_t));
    if (instance == NULL) return STUN_MEM_ERROR;

    instance->max_allocs = max_allocs;
    instance->nonce_timeout = TURNS_ALLOCATION_NONCE_STALE_TIMER;

    status = turns_create_table(max_allocs, &(instance->h_table));
    if (status != STUN_OK) return status;

    /** initialize all the allocations */
    status = turns_table_init_allocations(instance->h_table);
    if (status != STUN_OK) return status;

#ifndef MB_STATELESS_TURN_SERVER
    status = stun_txn_create_instance(
                TURN_MAX_CONCURRENT_SESSIONS, &instance->h_txn_inst);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_EMERG, 
                "TURNS: Failed to create transaction instance");
        goto MB_ERROR_EXIT;
    }
#else
    ICE_LOG(LOG_SEV_INFO, 
            "Transaction layer disabled. Running as a stateless server");
#endif

    /** TODO - reserve a block of ports now itself? */
        
    *h_inst = (handle) instance;

    return status;

MB_ERROR_EXIT:
    turns_destroy_table(instance->h_table);
    stun_free(instance);
    return status;
}


#ifndef MB_STATELESS_TURN_SERVER

int32_t turns_nwk_cb_fxn (handle h_msg, handle h_param)
{
    ICE_LOG(LOG_SEV_CRITICAL, "Please send me out");
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
#endif /** MB_STATELESS_TURN_SERVER */



int32_t turns_instance_set_osa_callbacks(
                        handle h_inst, turns_osa_callbacks_t *cbs)
{
    turns_instance_t *instance;
    int32_t status = STUN_OK;
#ifndef MB_STATELESS_TURN_SERVER
    stun_txn_instance_callbacks_t app_cbs;
#endif

    if ((h_inst == NULL) || (cbs == NULL))
        return STUN_INVALID_PARAMS;

    if ((cbs->nwk_data_cb == NULL) || (cbs->nwk_stun_cb == NULL) || 
            (cbs->start_timer_cb == NULL) || (cbs->stop_timer_cb == NULL))
    {
        return STUN_INVALID_PARAMS;
    }

    instance = (turns_instance_t *) h_inst;

    instance->nwk_stun_cb = cbs->nwk_stun_cb;
    instance->nwk_data_cb = cbs->nwk_data_cb;
    instance->new_socket_cb = cbs->new_socket_cb;
    instance->remove_socket_cb = cbs->remove_socket_cb;
    instance->start_timer_cb = cbs->start_timer_cb;
    instance->stop_timer_cb = cbs->stop_timer_cb;

#ifndef MB_STATELESS_TURN_SERVER
    /** propagate app callbacks to stun txn */
    app_cbs.nwk_cb = turns_nwk_cb_fxn;
    app_cbs.start_timer_cb = turns_start_txn_timer;
    app_cbs.stop_timer_cb = turns_stop_txn_timer;

    status = stun_txn_instance_set_callbacks(instance->h_txn_inst, &app_cbs);
#endif

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



int32_t turns_instance_set_nonce_stale_timer_value(
                                handle h_inst, uint32_t timeout)
{
    turns_instance_t *instance;

    if ((h_inst == NULL) || (timeout == 0))
        return STUN_INVALID_PARAMS;

    instance = (turns_instance_t *) h_inst;

    instance->nonce_timeout = timeout;

    return STUN_OK;
}



void turns_allocation_terminate(handle h_alloc, turns_allocation_t *alloc)
{
    int32_t status;

    printf("terminate me NOW table: %p allocation: %p\n", h_alloc, alloc);

    status = turns_allocation_fsm_inject_msg(
                                alloc, TURNS_ALLOC_TERMINATE, NULL);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                    "Unable to terminate the allocation: %d", status);
    }

    return;
}



int32_t turns_destroy_instance(handle h_inst)
{
    turns_instance_t *instance;
    turns_alloc_iteration_cb cb = turns_allocation_terminate;

    if (h_inst == NULL)
        return STUN_INVALID_PARAMS;

    instance = (turns_instance_t *) h_inst;

    /** iterate on all allocations and terminate them */
    turns_table_iterate(instance->h_table, cb);

    /** deinitialize all the allocations */
    turns_table_deinit_allocations(instance->h_table);

    /** destory the table */
    turns_destroy_table(instance->h_table);

#ifndef MB_STATELESS_TURN_SERVER
    stun_txn_destroy_instance(instance->h_txn_inst);
#endif
    
    if (instance->client_name) stun_free(instance->client_name);
    if (instance->realm) stun_free(instance->realm);

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
    status = turns_table_find_node(instance->h_table, &stun_pkt->src, 
                stun_pkt->transport_param, stun_pkt->protocol, &alloc_ctxt);

    /** 
     * TODO - need to handle error scenarios as defined in 
     * RFC 5766 sec 6.2.  Receiving an Allocate Request checks 1-8
     */

    /** if found, then inject into the allocation fsm */
    if (status == STUN_OK)
    {
        turns_alloc_event_t event;

        /** inject into the turns allocation fsm */
        ICE_LOG(LOG_SEV_DEBUG, "TURNS allocation context found.");

        stun_msg_get_method(stun_pkt->h_msg, &method);
        stun_msg_get_class(stun_pkt->h_msg, &msg_type);

        /** TODO - need to do anything for indications */

        if ((msg_type != STUN_REQUEST) && (msg_type != STUN_INDICATION))
        {
            ICE_LOG(LOG_SEV_DEBUG, "Some stray response/indication. Ignoring");
            /** TODO - destroy the received message? mem leak? */
            return STUN_OK;
        }

        if (method == STUN_METHOD_ALLOCATE)
            event = TURNS_ALLOC_REQ;
        else if (method == STUN_METHOD_CREATE_PERMISSION)
            event = TURNS_PERM_REQ;
        else if (method == STUN_METHOD_CHANNEL_BIND)
            event = TURNS_CHNL_BIND_REQ;
        else if (method == STUN_METHOD_REFRESH)
            event = TURNS_REFRESH_REQ;
        else if (method == STUN_METHOD_SEND)
            event = TURNS_SEND_IND;
        else
            event = TURNS_ALLOC_EVENT_MAX;

        /** TODO: for unhandlesd messages, should they be destroyed? mem leak?*/
        if (event == TURNS_ALLOC_EVENT_MAX) return STUN_OK;

        status = turns_allocation_fsm_inject_msg(alloc_ctxt, event, stun_pkt);

        return STUN_OK;
    }

    /** 
     * if not found, and if ALLOCATE request, validate the request and notify
     * the server application about the incoming new allocation request.
     * Subsequently, if the server application approves the allocation, then
     * the new allocation context is created.
     */
    ICE_LOG(LOG_SEV_DEBUG, "TURNS allocation context NOT found.");
    
    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    status = stun_msg_get_class(stun_pkt->h_msg, &msg_type);

    if((method == STUN_METHOD_ALLOCATE) && (msg_type == STUN_REQUEST))
    {
        handle h_resp;
        //uint32_t error_code = 0;
        //turns_new_allocation_params_t *params;

        ICE_LOG(LOG_SEV_DEBUG, "This is a NEW allocate request.");

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
        alloc_ctxt = turns_table_create_allocation(instance->h_table);
        if (alloc_ctxt == NULL)
        {
            ICE_LOG(LOG_SEV_CRITICAL, 
                    "Creation of new allocation context failed: [%d]\n", status);
            return STUN_MEM_ERROR;
        }

        ICE_LOG(LOG_SEV_DEBUG, 
                "New allocation context created: [%p]", alloc_ctxt);

        status = 
            turns_utils_init_allocation_context(instance, alloc_ctxt, stun_pkt);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Initialization of the "\
                    "new allocation context failed: [%d]", status);
            return STUN_MEM_ERROR;
        }

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
                instance->nwk_stun_cb(h_resp, 
                        stun_pkt->src.host_type, stun_pkt->src.ip_addr, 
                        stun_pkt->src.port, stun_pkt->transport_param, NULL);

                ICE_LOG(LOG_SEV_DEBUG, 
                        "TURNS: sent error response with error code: 401");
                
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
        /**
         * TODO - rfc 5766 sec 4 - General Behavior
         * For all TURN messages (including ChannelData) EXCEPT an Allocate 
         * request, if the 5-tuple does not identify an existing allocation, 
         * then the message MUST either be rejected with a 437 Allocation 
         * Mismatch error (if it is a request) or silently ignored (if it 
         * is an indication or a ChannelData message).
         */
         ICE_LOG(LOG_SEV_DEBUG, "Ignoring a stray STUN/TURN message");
    }
    
    return status;
}



int32_t turns_inject_received_channeldata_msg(
                handle h_inst, turns_rx_channel_data_t *chnl_data)
{
    int32_t status;
    turns_instance_t *instance = (turns_instance_t *)h_inst;
    turns_allocation_t *alloc_ctxt = NULL;

    /** 
     * determine the allocation context for this message. In case of TCP, we 
     * could use the socket descriptor to identify the allocation context. 
     * However in case of UDP, the allocation can possibly be identified only 
     * by the 5-tuple. At the server, the 5-tuple value consists of client's 
     * server-reflexive address, the server transport address and the transport 
     * protocol.
     */
    status = turns_table_find_node(instance->h_table, &chnl_data->src, 
                chnl_data->transport_param, chnl_data->protocol, &alloc_ctxt);

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Did not find any allocation for the "\
                "received channeldata message. Hence dropping the message");
        /** TODO - should we destroy the message? memleak? */
        return status;
    }

    status = turns_allocation_fsm_inject_msg(
                    alloc_ctxt, TURNS_CHNL_DATA_IND, chnl_data);

    return status;
}



int32_t turns_inject_timer_event(handle timer_id, handle arg)
{
    int32_t status;
    turns_timer_params_t *timer;
    turns_allocation_t *alloc;
    turns_instance_t *instance;

    if ((timer_id == NULL) || (arg == NULL))
        return STUN_INVALID_PARAMS;

    timer = (turns_timer_params_t *) arg;
    alloc = (turns_allocation_t *)timer->h_alloc;
    instance = (turns_instance_t *)timer->h_instance;

    /** make sure we allocation is valid & alive before injecting the event */
    status = turns_table_does_node_exist(instance->h_table, timer->h_alloc);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG (LOG_SEV_INFO, 
            "[TURN] Some stray TURNS timer. Ignoring for now");
        return STUN_OK;
    }

    /**
     * Note: since the allocations are allocated on memory and shared between 
     * processes, sometimes when an allocation is deleted we might not be 
     * able to stop the timer. In such a case we are not doing anything to 
     * mark that this timer is running, so that this can be handled 
     * gracefully later. Now suppose, the same allocation context is 
     * allocated again and then this old unstopped timer fires, then we get 
     * to the same context again. But this timer event does not legally 
     * belong to the current allocation.
     */

    switch (timer->type)
    {
#ifndef MB_STATELESS_TURN_SERVER
#if 0
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
#endif
#endif /** MB_STATELESS_TURN_SERVER */

        case TURNS_ALLOC_TIMER:
            if (alloc->alloc_timer_params.timer_id == timer->timer_id)
            {
                status= turns_allocation_fsm_inject_msg(
                                alloc, TURNS_ALLOC_TIMER_EXP, NULL);
            }
            else
            {
                ICE_LOG(LOG_SEV_NOTICE, "Some stray unknown allocation "\
                        "refresh timer id fired. Filtering out...");
            }
            break;

        case TURNS_NONCE_TIMER:
            if (alloc->nonce_timer_params.timer_id == timer->timer_id)
            {
                status= turns_allocation_fsm_inject_msg(
                                alloc, TURNS_NONCE_TIMER_EXP, NULL);
            }
            else
            {
                ICE_LOG(LOG_SEV_NOTICE, "Some stray unknown allocation "\
                        "nonce stale timer id fired. Filtering out...");
            }
            break;

        case TURNS_PERM_TIMER:
            status= turns_allocation_fsm_inject_msg(
                            alloc, TURNS_PERM_TIMER_EXP, arg);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_NOTICE, "Some stray unknown permission "\
                        "timer id fired. Filtering out...");
            }
            break;

        case TURNS_CHNL_TIMER:
            status= turns_allocation_fsm_inject_msg(
                            alloc, TURNS_CHNL_BIND_TIMER_EXP, arg);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_NOTICE, "Some stray unknown channel bind "\
                        "timer id fired. Filtering out...");
            }
            break;

        default:
            status = STUN_INVALID_PARAMS;
            break;
    }

    return status;
}



int32_t turns_inject_allocation_decision(
            handle h_inst, turns_allocation_decision_t *decision)
{
    int32_t status;
    turns_alloc_event_t event = TURNS_ALLOC_EVENT_MAX;

    /** TODO - make sure the allocation context exists before injecting */

    if (decision->approved == true)
        event = TURNS_ALLOC_APPROVED;
    else
        event = TURNS_ALLOC_REJECTED;

    status = turns_allocation_fsm_inject_msg(decision->blob, event, decision);

    return status;
}



int32_t turns_inject_received_udp_msg(
                handle h_inst, turns_rx_channel_data_t *udp_data)
{
    int32_t status;
    turns_instance_t *instance = (turns_instance_t *)h_inst;
    turns_allocation_t *alloc_ctxt = NULL;

    /*
     * RFC 5766 section 10.3 - Receiving a UDP datagram.
     * When the server receives a UDP datagram at a currently allocated
     * relayed transport address, the server looks up the allocation
     * associated with the relayed transport address.
     */
    status = turns_table_find_node_for_relayed_transport_address(
                instance->h_table, udp_data->transport_param, 
                ICE_TRANSPORT_UDP, &alloc_ctxt);

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_NOTICE, "Did not find any allocation for the "\
                "received channeldata message. Hence dropping the message");
        return status;
    }

    status = turns_allocation_fsm_inject_msg(
                    alloc_ctxt, TURNS_MEDIA_DATA, udp_data);

    return status;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
