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
#include "turns_alloc_fsm.h"



static turns_alloc_fsm_handler 
    turns_alloc_fsm[TSALLOC_STATE_MAX][TURNS_ALLOC_EVENT_MAX] =
{
    /** TSALLOC_CHALLENGED */
    {
        turns_process_alloc_req,
        turns_ignore_msg,
        turns_ignore_msg,
    },
    /** TSALLOC_PENDING */
    {
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
    /** TSALLOC_CHALLENGED */
    {
        turns_ignore_msg,
        turns_ignore_msg,
        turns_ignore_msg,
    },
};



int32_t turns_process_alloc_req (turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    uint32_t error_code;
    turns_new_allocation_params_t *params;
    turns_rx_stun_pkt_t *stun_pkt = (turns_rx_stun_pkt_t *) h_msg;

    params = (turns_new_allocation_params_t *) 
            stun_calloc (1, sizeof(turns_new_allocation_params_t));
    if (params == NULL) return STUN_MEM_ERROR;


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
            alloc->instance->nwk_send_cb(h_resp, 
                    stun_pkt->src.host_type, stun_pkt->src.ip_addr, 
                    stun_pkt->src.port, stun_pkt->transport_param, NULL);

            printf("turns: sent error response with error code: %d\n", error_code);
        }
        else
        {
            printf("TODO: Need to handle error in this case\n");
        }
    }

    /** if we are here, then allocation request is ok */
    printf ("We are good to go\n");

    /** TODO - need to feed it to transaction module */

    /** pass up the allocation request to server app for approval */
    status = turns_utils_notify_new_alloc_request_to_app(alloc);

    if (status == STUN_OK) alloc->state = TSALLOC_PENDING;

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
        //status = turn_session_utils_notify_state_change_event(session);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
