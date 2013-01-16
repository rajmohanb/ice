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
#include "turns_utils.h"
#include "turns_table.h"
#include "turns_alloc_fsm.h"



static turns_alloc_fsm_handler 
    turns_alloc_fsm[TSALLOC_STATE_MAX][TURNS_ALLOC_EVENT_MAX] =
{
    /** TSALLOC_UNALLOCATED */
    {
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
    /** TSALLOC_CHALLENGED */
    {
        turns_process_alloc_req,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
    /** TSALLOC_PENDING */
    {
        turns_ignore_msg,
        turns_alloc_accepted,
        turns_alloc_rejected,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_generate_new_nonce,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
    /** TSALLOC_ALLOCATED */
    {
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_refresh_req,
        turns_process_alloc_timer,
        turns_create_perm_req,
        turns_channel_bind_req,
        turns_send_ind,
        turns_media_data,
        turns_generate_new_nonce,
        turns_channel_bind_timer,
        turns_perm_timer,
        turns_channel_data_ind,
    },
    /** TSALLOC_TERMINATING */
    {
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
};



int32_t turns_process_alloc_req (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    uint32_t error_code;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;

    /** TODO:
     * If this is a re-transmission of the original ALLOCATE request without
     * credentials, then it needs to be dealt with - by sending the 401
     * challenge response. This could be done either within the transaction
     * layer module by holding on to the transaction context till the 
     * transaction times out by defining some timer. Otherwise, we can create
     * and send a response from here.
     *
     * for now - if this is a re-transmission, we are ignoring it. But we
     * need to handle this either way as defined above asap.
     */
    status = turns_utils_verify_info_from_alloc_request(
                                    alloc, stun_pkt->h_msg, &error_code);
    if(status != STUN_OK)
    {
        if (error_code == 401)
        {
            handle h_resp;

            status = turns_utils_create_error_response(
                            alloc, stun_pkt->h_msg, error_code, &h_resp);
            // TODO check status? remove txn? graceful exit?
            if(status != STUN_OK) return status;

            /** send the response directly, not using the txn module */
            alloc->instance->nwk_stun_cb(h_resp, 
                    stun_pkt->src.host_type, stun_pkt->src.ip_addr, 
                    stun_pkt->src.port, stun_pkt->transport_param, NULL);

            printf("turns: sent error response with error code: %d\n", error_code);
        }
        else
        {
            printf("TODO: Need to handle error in this case\n");
        }

        return STUN_OK;
    }

    /** if we are here, then allocation request is ok */
    alloc->h_req = stun_pkt->h_msg;

    /** TODO - need to feed it to transaction module */

    /** pass up the allocation request to server app for approval */
    status = turns_utils_notify_new_alloc_request_to_app(alloc);

    if (status == STUN_OK) alloc->state = TSALLOC_PENDING;

    return status;
}


int32_t turns_alloc_accepted (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    handle h_resp;
    turns_allocation_decision_t *decision = 
                (turns_allocation_decision_t *) h_msg;

    /** update the allocation context parameters */
    alloc->initial_lifetime = decision->lifetime;
    alloc->lifetime = alloc->initial_lifetime;
    memcpy(&alloc->hmac_key, &decision->key, TURNS_HMAC_KEY_LEN);

    /** setup the allocation */
    status = turns_utils_setup_allocation(alloc);
    if (status != STUN_OK)
    {
        /** TODO - shouldn't we send some error response? */
        printf("Unable to allocate and allocation failed\n");
        return status;
    }

    /** send the success allocation response */
    status = turns_utils_create_success_response(alloc, alloc->h_req, &h_resp);
    if (status == STUN_OK)
    {
        alloc->h_resp = h_resp;

        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        printf("Sent the allocation success response\n");

        alloc->state = TSALLOC_ALLOCATED;

        /** start allocation timer */
        status = turns_utils_start_alloc_timer(alloc);

        if (status == STUN_OK)
        {
            /** notify the application about the new socket to listen to */
            alloc->instance->new_socket_cb(alloc, alloc->relay_sock);
        }
    }

    return status;
}


int32_t turns_alloc_rejected (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    handle h_resp;
    turns_allocation_decision_t *decision = 
                (turns_allocation_decision_t *) h_msg;

    /** send the error response */
    status = turns_utils_create_error_response(alloc, 
                                alloc->h_req, decision->code, &h_resp);
    if (status == STUN_OK)
    {
        alloc->h_resp = h_resp;

        /** send the error response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        printf("Sent the allocation success response\n");
    }
    else
    {
        printf("Error while creating the "\
                "allocation error response: [%d]\n", status);
    }

    /** we need to anyway tear down this allocation */
    alloc->state = TSALLOC_UNALLOCATED;
    status = STUN_TERMINATED;

    return status;
}


int32_t turns_refresh_req (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    uint32_t error_code;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;
    handle h_resp;

    printf("Received Allocation REFRESH request\n");

    /** don't stop the alloc timer yet */

    /** authenticate the request */
    status = turns_utils_verify_request(alloc, stun_pkt->h_msg, &error_code);
    
    if (status != STUN_OK)
    {
        /** send error response */
        status = turns_utils_create_error_response(
                            alloc, stun_pkt->h_msg, error_code, &h_resp);

        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        /** TODO - check if sending succeeded */

        printf("Sent the allocation error response: %d\n", error_code);

        return status;
    }

    /** extract the refresh specific attribute parameters */
    status = turns_utils_verify_info_from_refresh_request(
                                        alloc, stun_pkt->h_msg, &error_code);
    if (status == STUN_NOT_FOUND)
    {
        /** 
         * optional lifetime attribute missing, use the existing 
         * lifetime value for refreshing the allocation.
         */
        alloc->lifetime = alloc->initial_lifetime;
    }
    else if (status == STUN_OK)
    {
        if (alloc->lifetime == 0)
        {
            /** 
             * client is requesting to delete the allocation. 
             * we do not need to do anything here, it is 
             * taken care of down below in this routine 
             */
        }
        else
        {
            /** re-calculate the new lifetime value for the allocation */
            if (alloc->lifetime > alloc->initial_lifetime)
                alloc->lifetime = alloc->initial_lifetime;
        }
    }
    else
    {
        printf("Error while retrieving attribute values from "\
                "refresh request. Hence sending error response 400\n");

        status = turns_utils_create_error_response(
                            alloc, stun_pkt->h_msg, error_code, &h_resp);

        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        /** TODO - check if sending succeeded */

        printf("Sent the allocation error response: %d\n", error_code);

        return status;
    }


    /** send success response */
    status = turns_utils_create_success_response(
                                alloc, stun_pkt->h_msg, &h_resp);
    if (status == STUN_OK)
    {
        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        /** TODO - check if sending succeeded */

        printf("Sent the allocation success response\n");

        if (alloc->lifetime == 0)
        {
            /** 
             * TODO - need to come back here... how will this 
             * allocation move to TSALLOC_UNALLOCATED? 
             */
            alloc->state = TSALLOC_TERMINATING;
        }
        else
        {
            /** restart the alloc timer with modified duration if required */
            status = turns_utils_stop_alloc_timer(alloc);
            if (status != STUN_OK)
            {
                /** TODO */
                printf("Unable to stop the allocation timer! what's next? \n");
            }
            else
            {
                printf("Stopped the current alloc timer:\n");
            }

            status = turns_utils_start_alloc_timer(alloc);

            /** else no change in allocation state */
        }
    }
    
    return status;
}



int32_t turns_send_ind (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;

    printf("Received Send indication message\n");

    status = turns_utils_forward_send_data(alloc, stun_pkt->h_msg);

    return status;
}



int32_t turns_channel_data_ind (turns_allocation_t *alloc, handle h_msg)
{
    printf("Received Channel Data indication message\n");

    return turns_utils_forward_channel_data(alloc, h_msg);
}



int32_t turns_process_alloc_timer (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;

    printf("Allocation timer expired. Lets unallocate it now\n");

    status = turns_utils_deinit_allocation_context(alloc);

    alloc->state = TSALLOC_UNALLOCATED;

    return status;
}



int32_t turns_channel_bind_timer (turns_allocation_t *alloc, handle h_msg)
{
    turns_permission_t *perm;
    turns_timer_params_t *timer = (turns_timer_params_t *) h_msg;

    printf("Channel Bind timer expired. Lets remove the binding now\n");

    /** 
     * the channel binding and the associated permission 
     * has not been validated so far, so do it now.
     */
    perm = turns_utils_validate_allocation_channel_binding(alloc, timer->arg);
    if (!perm)
    {
        /** The channel binding does not exist! or has been uninstalled */
        printf("The channel binding for the channel binding timer does not exist\n");
        return STUN_OK;
    }

    /** double check the timer id */
    if (perm->h_channel_timer != timer->timer_id)
    {
        printf("Unknown channel bind timer?? \n");
        printf("perm->h_channel_timer [%p] and timer->timer_id [%p]\n", 
                perm->h_channel_timer, timer->timer_id);
        return STUN_OK;
    }

    /* 
     * remove the channel binding referred to by the channel binding 
     * timer. The permission might continue to live because the 
     * permission refresh mechanism is different from channel binding
     */
    perm->channel_num = 0;
    perm->h_channel_timer = NULL;
    perm->channel_timer.timer_id = NULL;

    printf("Un-installed channel binding\n");

    return STUN_OK;
}



int32_t turns_perm_timer (turns_allocation_t *alloc, handle h_msg)
{
    turns_permission_t *perm;
    turns_timer_params_t *timer = (turns_timer_params_t *) h_msg;

    printf("Permission timer expired. Lets remove the permission now\n");

    /** validated the expired permission handle */
    perm = turns_utils_validate_permission_handle(alloc, timer->arg);
    if (!perm)
    {
        /** The permission does not exist! or has been uninstalled */
        printf("The permission for the permission timer does not exist\n");
        return STUN_OK;
    }

    /** double check the timer id */
    if (perm->h_perm_timer != timer->timer_id)
    {
        printf("Unknown permission timer??\n");
        printf("perm->h_perm_timer [%p] and timer->timer_id [%p]\n", 
                perm->h_perm_timer, timer->timer_id);
        return STUN_OK;
    }

    /** remove the installed permission */
    perm->channel_num = 0;
    perm->h_channel_timer = NULL;
    perm->channel_timer.timer_id = NULL;

    printf("Un-installed permission\n");

    return STUN_OK;
}



int32_t turns_generate_new_nonce(turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;

    printf("Allocation nonce stale timer expired. Generate a new one\n");

    /** generate new random nonce */
    turns_generate_nonce_value((char *)alloc->nonce, TURNS_SERVER_NONCE_LEN);

    /** start the nonce stale timer */
    status = turns_utils_start_nonce_stale_timer(alloc);
    if (status != STUN_OK)
        printf("Unable to start the nonce stale timer\n");

    /** remain in the same state */

    return status;
}



int32_t turns_create_perm_req(turns_allocation_t *alloc, handle h_msg)
{
    handle h_resp;
    int32_t status;
    uint32_t error_code;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;

    printf("Received the CREATE PERMISSION request\n");

    /** authenticate the request */
    status = turns_utils_verify_request(alloc, stun_pkt->h_msg, &error_code);
    if (status != STUN_OK)
    {
        /** send error response */
        status = turns_utils_create_error_response(
                            alloc, stun_pkt->h_msg, error_code, &h_resp);

        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        /** TODO - check if sending succeeded */

        printf("Sent the allocation error response: %d\n", error_code);

        return status;
    }

    status = 
        turns_utils_handle_create_permission_request(alloc, stun_pkt->h_msg);

    return status;
}

 

int32_t turns_channel_bind_req(turns_allocation_t *alloc, handle h_msg)
{
    handle h_resp;
    int32_t status;
    uint32_t error_code;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;

    printf("Received the CHANNEL BIND request\n");

    /** 
     * check if there is already a channel number associated with this 
     * address. The client can bind a channel to a peer at any time
     * during the lifetime of the allocation. The client may bind a
     * channel to a peer before exchanging data with it, or after 
     * exchanging data with it (using Send and Data indications) for
     * some time, or may choose never to bind a channel to it. The
     * client can also bind channels to some peers while not binding 
     * channels to other peers.
     */

    /** authenticate the request */
    status = turns_utils_verify_request(alloc, stun_pkt->h_msg, &error_code);
    if (status != STUN_OK)
    {
        /** send error response */
        status = turns_utils_create_error_response(
                            alloc, stun_pkt->h_msg, error_code, &h_resp);

        /** send the success response */
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, alloc->hmac_key);

        /** TODO - check if sending succeeded */

        printf("Sent the allocation error response: %d\n", error_code);

        return status;
    }

    status = turns_utils_handle_channel_bind_request(alloc, stun_pkt->h_msg);

    return status;
}


int32_t turns_media_data (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    turns_permission_t *perm;
    turns_rx_channel_data_t *data = (turns_rx_channel_data_t *) h_msg;

    /** 
     * RFC 5766 section 10.3 Receiving a UDP datagram
     * The server then checks to see whether the set of permissions for the 
     * allocation allow the relaying of the UDP datagram as described in 
     * Section 8.
     */
    perm = turns_utils_search_for_permission(alloc, data->src);
    if (perm == NULL)
    {
        /** silently discard the UDP datagram */
        printf("Permission not found for the received "\
                "UDP datagram. Hence discarding the UDP datagram"); 
        return STUN_OK;
    }

    if (perm->channel_num && perm->h_channel_timer)
    {
        /**
         * if relaying is permitted and channel is bound 
         * to the peer, ChannelData message is sent.
         */
        status = turns_utils_forward_udp_data_using_channeldata_msg(
                                                            alloc, perm, data);
    }
    else
    {
        /*
         * If relaying is permitted but no channel is bound to the 
         * peer, then the server forms and sends a Data indication.
         */
        status = turns_utils_forward_udp_data_using_data_ind(alloc, perm, data);
    }

    return status;
}


int32_t turns_ignore_msg (turns_allocation_t *alloc, handle h_msg)
{
    printf ("TURNS ALLOCATION FSM: Ignoring the event\n");
    return STUN_OK;
}


int32_t turns_allocation_fsm_inject_msg(turns_allocation_t *alloc, 
                                    turns_alloc_event_t event, handle h_msg)
{
    int32_t status;
    turns_alloc_state_t cur_state;
    turns_alloc_fsm_handler handler;

    cur_state = alloc->state;
    handler = turns_alloc_fsm[cur_state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(alloc, h_msg);

    if (cur_state != alloc->state)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "TURN session %p moved to state %d from %d", 
                alloc, alloc->state, cur_state);
    }

    if (alloc->state == TSALLOC_UNALLOCATED)
    {
        /** 
         * if a context has been unallocated, then mark the node in 
         * the context list as unused so that this can be reused.
         */
        if (turns_table_delete_allocation(
                    alloc->instance->h_table, alloc) != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "TURN session %p: Unable to move it to unused", alloc);
        }
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
