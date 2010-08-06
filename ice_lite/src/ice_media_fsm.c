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


#include "types.h"
#include "msg_layer_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "conn_check_api.h"
#include "ice_utils.h"
#include "ice_media_fsm.h"


static ice_media_stream_fsm_handler 
    ice_media_stream_fsm[ICE_MEDIA_CC_STATE_MAX][ICE_MEDIA_CC_EVENT_MAX] =
{
    /** ICE_MEDIA_CC_IDLE */
    {
        ice_media_lite_mode,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_CC_RUNNING */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_rx_msg,
        ice_media_stream_restart,
        ice_media_stream_remote_params,
        ice_media_stream_dual_ice_lite,
    },
    /** ICE_MEDIA_CC_COMPLETED */
    {
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_restart,
        ice_media_stream_remote_params,
        ice_media_stream_ignore_msg,
    },
    /** ICE_CC_MEDIA_FAILED */
    {
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    }
};




int32_t ice_media_process_rx_msg(ice_media_stream_t *media, handle pkt)
{
    int32_t status;
    handle h_cc_inst, h_cc_dialog;
    ice_rx_stun_pkt_t *stun_pkt = (ice_rx_stun_pkt_t *) pkt;

    h_cc_inst = media->ice_session->instance->h_cc_inst;

    ICE_LOG(LOG_SEV_DEBUG, "Received message from %s and port %d", 
                                stun_pkt->src.ip_addr, stun_pkt->src.port);

    /** 
     * find out if the received stun packet belongs to 
     * one of existing connectivity check session 
     */
    status = conn_check_find_session_for_recv_msg(
                                    h_cc_inst, stun_pkt->h_msg, &h_cc_dialog);
    if (status == STUN_NOT_FOUND)
    {
        stun_msg_type_t msg_class;

        stun_msg_get_class(stun_pkt->h_msg, &msg_class);

        if (msg_class != STUN_REQUEST)
        {
            ICE_LOG (LOG_SEV_DEBUG, 
                    "Discarding the stray stun response message");
            return STUN_OK;
        }

        /** create new incoming connectivity check dialog */
        status = ice_utils_create_conn_check_session(media, stun_pkt);
        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                "ice_utils_create_conn_check_session() returned error %d\n", 
                status);
            return STUN_INT_ERROR;
        }

        status = conn_check_session_inject_received_msg(
                        h_cc_inst, media->h_cc_svr_session, stun_pkt->h_msg);
        if (status == STUN_TERMINATED)
        {
            bool_t nominated;

            status = conn_check_session_get_nominated_state(
                                h_cc_inst, media->h_cc_svr_session, &nominated);
            if (status != STUN_OK) return status;

            /** if nominated, then add it to the list of valid pairs */
            if (nominated == true)
            {
                int32_t i;
                ice_cand_pair_t *valid_pair;

                for (i = 0; i < ICE_MAX_CANDIDATE_PAIRS; i++)
                {
                    valid_pair = &media->ah_valid_pairs[i];
                    if (valid_pair->local == NULL)
                        break;
                }

                ICE_LOG (LOG_SEV_INFO, 
                    "USE-CANDIDATE is set for this connectivity check request");

                if (i == ICE_MAX_CANDIDATE_PAIRS)
                {
                    ICE_LOG (LOG_SEV_WARNING, 
                        "Exceeded the cofigured list of valid pair entries");
                }
                else
                {
                    valid_pair->local = 
                        ice_utils_get_local_cand_for_transport_param(media, stun_pkt->transport_param);
                    valid_pair->remote = 
                        ice_utils_get_peer_cand_for_pkt_src(media, &(stun_pkt->src));

                    if (valid_pair->remote == NULL)
                    {
                        ICE_LOG (LOG_SEV_WARNING, 
                            "Ignored binding request from unknown source");
                    }
                }

                if(ice_media_utils_have_valid_list(media) == true)
                {
                    media->state = ICE_MEDIA_CC_COMPLETED;
                }
            }

            conn_check_destroy_session(h_cc_inst, media->h_cc_svr_session);
            media->h_cc_svr_session = NULL;
        }
        else if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                "conn_check_session_inject_received_msg() returned error %d\n", 
                status);
            return STUN_INT_ERROR;
        }

    } else if (status == STUN_OK)
    {
    }
    else
    {
    }

    return STUN_OK;
}



int32_t ice_media_lite_mode(ice_media_stream_t *media, handle arg)
{
    media->state = ICE_MEDIA_CC_RUNNING;

    return STUN_OK;
}


int32_t ice_media_stream_restart(ice_media_stream_t *media, handle arg)
{
    int32_t status;

    /** 
     * RFC 5245 sec 9.3.2 Procedures for Lite Implementation
     * If ICE is restarting for a media stream, the agent MUST start a new
     * Valid list for that media stream.  It MUST remember the pairs in the
     * previous Valid list for each component of the media stream, called
     * the previous selected pairs, and continue to send media there as
     * described in Section 11.1.  The state of ICE processing for each
     * media stream MUST change to Running, and the state of ICE processing
     * MUST change to Running.
     */
    status = ice_media_utils_copy_selected_pair(media);

    if (status == STUN_OK)
    {
        media->state = ICE_MEDIA_CC_RUNNING;

        /** flush the valid list and the computed check list */
        stun_memset(media->ah_cand_pairs, 0,
                ICE_MAX_CANDIDATE_PAIRS * sizeof(ice_cand_pair_t));
        stun_memset(media->ah_valid_pairs, 0,
                ICE_MAX_CANDIDATE_PAIRS * sizeof(ice_cand_pair_t));
    }

    return status;
}


int32_t ice_media_stream_remote_params(ice_media_stream_t *media, handle h_msg)
{
    int32_t status;
    ice_media_params_t *media_params = (ice_media_params_t *)h_msg;

    status = ice_utils_set_peer_media_params(media, media_params);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Setting of remote params failed for media %p", media);
        return status;
    }

    /**
     * if the offer received from remote contained remote-candidates 
     * attribute, then the state of ICE processing for that media
     * stream is set to COMPLETED.
     */
    if (media_params->comps[0].num_remote_cands > 0)
    {
        media->state = ICE_MEDIA_CC_COMPLETED;

        if ((media->ice_session->local_mode == ICE_MODE_LITE) &&
            (media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING))
        {
            /**
             * Further as per sec 9.2.3 Ice lite mode
             * If this agent believed it was controlling and the peer
             * also indicated that it thinks it is controlling (by sending
             * remote-candidates), then the 'winner' is decided by the 
             * SDP offer-answer negotiation. And the answerer (this agent)
             * must change it's role to controlled.
             */
            media->ice_session->role = ICE_AGENT_ROLE_CONTROLLED;
        }
    }

    return status;
}


int32_t ice_media_stream_dual_ice_lite(ice_media_stream_t *media, handle h_msg)
{
    int32_t status;

    /**
     * This event is injected by the session fsm when this ice session is
     * in ice-lite mode and the peer also is also in ice-lite mode.
     */
    status = ice_media_utils_form_candidate_pairs(media);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Forming of candidates failed for media %p", media);
        return status;
    }

    status = ice_utils_dual_lite_select_valid_pairs(media);

    return status;
}


int32_t ice_media_stream_ignore_msg(ice_media_stream_t *media, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_media_stream_fsm_inject_msg(ice_media_stream_t *media, 
                                ice_media_stream_event_t event, handle h_msg)
{
    int32_t status;
    ice_media_stream_state_t cur_state;
    ice_media_stream_fsm_handler handler;

    cur_state = media->state;
    handler = ice_media_stream_fsm[cur_state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(media, h_msg);

    if (cur_state != media->state)
    {
        ice_media_utils_notify_state_change_event(media);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
