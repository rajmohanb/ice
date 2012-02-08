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
#include "turn_api.h"
#include "stun_binding_api.h"
#include "ice_api.h"
#include "ice_int.h"
#include "conn_check_api.h"
#include "ice_utils.h"
#include "ice_cand_pair_fsm.h"
#include "ice_media_fsm.h"



static ice_media_stream_fsm_handler 
    ice_media_stream_fsm[ICE_MEDIA_STATE_MAX][ICE_MEDIA_EVENT_MAX] =
{
    /** ICE_MEDIA_CC_IDLE */
    {
        ice_media_stream_gather_cands,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_lite_mode,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_GATHERING */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_relay_msg,
        ice_media_stream_check_gather_resp,
        ice_media_stream_gather_failed,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_GATHERED */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_relay_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_form_checklist,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_process_rx_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_remote_params,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_FROZEN */
    {
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_unfreeze,
        ice_media_stream_ignore_msg,
        ice_media_process_rx_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_CC_RUNNING */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_relay_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_checklist_timer_expiry,
        ice_media_process_rx_msg,
        ice_media_stream_restart,
        ice_media_stream_remote_params,
        ice_media_stream_dual_ice_lite,
        ice_media_conn_check_timer_expiry,
        ice_media_stream_evaluate_valid_pairs,
        ice_media_stream_keep_alive_timer_expiry,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_NOMINATING */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_relay_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_checklist_timer_expiry,
        ice_media_process_rx_msg,
        ice_media_stream_restart,
        ice_media_stream_remote_params,
        ice_media_stream_dual_ice_lite,
        ice_media_conn_check_timer_expiry,
        ice_media_stream_ignore_msg,
        ice_media_stream_keep_alive_timer_expiry,
        ice_media_stream_ignore_msg,
    },
    /** ICE_MEDIA_CC_COMPLETED */
    {
        ice_media_stream_ignore_msg,
        ice_media_process_relay_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_checklist_timer_expiry,
        ice_media_process_rx_msg,
        ice_media_stream_restart,
        ice_media_stream_remote_params,
        ice_media_stream_ignore_msg,
        ice_media_conn_check_timer_expiry,
        ice_media_stream_ignore_msg,
        ice_media_stream_keep_alive_timer_expiry,
        ice_media_stream_send_data,
    },
    /** ICE_CC_MEDIA_FAILED */
    {
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_conn_check_timer_expiry,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
        ice_media_stream_ignore_msg,
    }
};



int32_t ice_media_stream_gather_cands(ice_media_stream_t *media, handle h_msg)
{
    uint32_t i;
    int32_t status;
    handle h_turn_inst = media->ice_session->instance->h_turn_inst;
    handle h_bind_inst = media->ice_session->instance->h_bind_inst;

    for (i = 0; i < media->num_comp; i++)
    {
        if (media->ice_session->use_relay == true)
        {
            status = ice_media_utils_init_turn_gather_candidates(
                                    media, h_turn_inst, 
                                    media->as_local_cands[i].transport_param, 
                                    &(media->h_turn_sessions[i]));
            if (status != STUN_OK) goto ERROR_EXIT;
        }
        else
        {
            status = ice_media_utils_init_stun_gather_candidates(
                                    media, h_bind_inst, 
                                    media->as_local_cands[i].transport_param, 
                                    &(media->h_bind_sessions[i]));
            if (status != STUN_OK) goto ERROR_EXIT;
        }
    }

    media->state = ICE_MEDIA_GATHERING;

    return status;

ERROR_EXIT:

    for (i = 0; i < media->num_comp; i++)
    {
        if (media->ice_session->use_relay == true)
        {
            if (media->h_turn_sessions[i])
                turn_destroy_session(h_turn_inst, media->h_turn_sessions[i]);
        }
        else
        {
            if (media->h_bind_sessions[i])
                stun_binding_destroy_session(
                                h_bind_inst, media->h_bind_sessions[i]);
        }
    }

    return status;
}



int32_t ice_media_process_relay_msg(ice_media_stream_t *media, handle h_msg)
{
    int32_t status;
    handle h_turn_inst, h_turn_dialog;
    handle h_bind_inst, h_bind_session;
    ice_rx_stun_pkt_t *stun_pkt = (ice_rx_stun_pkt_t *) h_msg;
    stun_method_type_t method;

    h_turn_inst = media->ice_session->instance->h_turn_inst;
    h_bind_inst = media->ice_session->instance->h_bind_inst;

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] Received message from %s and port %d", 
            stun_pkt->src.ip_addr, stun_pkt->src.port);

    status = stun_msg_get_method(stun_pkt->h_msg, &method);
    if (status != STUN_OK) return status;

    /** SEND messages are filtered out and ignored earlier */
    if (method == STUN_METHOD_DATA)
    {
        ICE_LOG(LOG_SEV_DEBUG,
                "[ICE MEDIA] **** Received indication message ****\n");

        h_turn_dialog = ice_utils_get_turn_session_for_transport_param(
                                            media, stun_pkt->transport_param);
        if (h_turn_dialog == NULL) status = STUN_INVALID_PARAMS;
    }
    else if (method == STUN_METHOD_BINDING)
    {
        status = stun_binding_instance_find_session_for_received_msg(
                                h_bind_inst, stun_pkt->h_msg, &h_bind_session);
    }
    else
    {
        /** 
         * find out if the received stun packet belongs to 
         * one of existing turn session
         */
        status = turn_instance_find_session_for_received_msg(
                                h_turn_inst, stun_pkt->h_msg, &h_turn_dialog);
    }

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE MEDIA] Unable to find a turn session for the "\
                "received message. Dropping the message");
        return status;
    }

    if (media->ice_session->use_relay == true)
    {
        status = turn_session_inject_received_msg(h_turn_inst, 
                                            h_turn_dialog, stun_pkt->h_msg);
    }
    else
    {
        status = stun_binding_session_inject_received_msg(
                                h_bind_inst, h_bind_session, stun_pkt->h_msg);
        if (status == STUN_TERMINATED)
        {
            status = ice_utils_copy_stun_gathered_candidates(
                            media, h_bind_inst, h_bind_session, stun_pkt);
            if (status == STUN_OK)
            {
                media->num_comp_gathered++;

                ICE_LOG(LOG_SEV_DEBUG, "[ICE MEDIA] Candidates gathered for "\
                        "%d number of components", media->num_comp_gathered);

                if (media->num_comp_gathered >= media->num_comp)
                {
                    media->state = ICE_MEDIA_GATHERED;

                    /** 
                     * 4.1.1.3 - Computing foundations
                     * Now that all the candidates have been gathered for 
                     * each of the components, the foundation id needs to 
                     * be computed which is used for the frozen algorithm
                     *
                     * TODO - should the foundation id be computed 
                     *        across all media streams?
                     */
                    ice_utils_compute_foundation_ids(media);
                }
            }
        }
    }

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_WARNING, 
                "[ICE MEDIA] BIND/TURN session returned error %d ", status);
        return status;
    }

    return status;
}



int32_t ice_media_stream_check_gather_resp(
                        ice_media_stream_t *media, handle h_msg)
{
    uint32_t comp_id;
    int32_t status;
    ice_int_params_t *param = (ice_int_params_t *)h_msg;

    status = ice_utils_validate_turn_session_handle(
                                    media, param->h_session, &comp_id);
    if (status != STUN_OK) return status;

    status = ice_utils_copy_turn_gathered_candidates(media, param, comp_id);

    media->num_comp_gathered++;

    ICE_LOG(LOG_SEV_DEBUG, "[ICE MEDIA] Candidates gathered for %d "\
            "number of components", media->num_comp_gathered);

    if (media->num_comp_gathered >= media->num_comp)
    {
        media->state = ICE_MEDIA_GATHERED;

        /** 
         * 4.1.1.3 - Computing foundations
         * Now that all the candidates have been gathered for each of the
         * components, the foundation id needs to be computed which is
         * used for the frozen algorithm
         * Note - should the foundation id be computed across all media streams?
         */
        ice_utils_compute_foundation_ids(media);
    }

    return STUN_OK;
}



int32_t ice_media_stream_gather_failed(
                        ice_media_stream_t *media, handle h_msg)
{
    uint32_t comp_id;
    int32_t status;
    ice_int_params_t *param = (ice_int_params_t *)h_msg;

    if (media->ice_session->use_relay == true)
    {
        status = ice_utils_validate_turn_session_handle(
                                    media, param->h_session, &comp_id);
    }
    else
    {
        status = ice_utils_validate_bind_session_handle(
                                    media, param->h_session, &comp_id);
    }

    if (status != STUN_OK) return status;

    ICE_LOG(LOG_SEV_ERROR,
            "[ICE MEDIA] Gathering of candidates failed for component %d "\
            "of media %p", comp_id, media);

    media->state = ICE_MEDIA_CC_FAILED;

    return STUN_OK;
}



int32_t ice_media_stream_form_checklist(
                    ice_media_stream_t *media, handle h_msg)
{
#ifdef DEBUG1
    uint32_t i;
#endif
    int32_t status;

#ifdef DEBUG1
    ICE_LOG (LOG_SEV_DEBUG, 
            "************************************************************\n");
    ICE_LOG (LOG_SEV_DEBUG, "Local candidates\n");
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        if (media->as_local_cands[i].priority == 0) continue;
        ICE_LOG (LOG_SEV_DEBUG, "Local candidate %p comp id %d\n", 
                &(media->as_local_cands[i]), media->as_local_cands[i].comp_id);
    }

    ICE_LOG (LOG_SEV_DEBUG, "Remote candidates\n");
    for (i = 0; i < ICE_CANDIDATES_MAX_SIZE; i++)
    {
        if (media->as_remote_cands[i].priority == 0) continue;
        ICE_LOG (LOG_SEV_DEBUG, "Remote candidate %p comp id %d\n", 
            &(media->as_remote_cands[i]), media->as_remote_cands[i].comp_id);
    }
    ICE_LOG (LOG_SEV_DEBUG, 
            "************************************************************\n");
#endif

    /** sec 5.7.1 forming candidate pairs */
    status = ice_media_utils_form_candidate_pairs(media);
    if (status != STUN_OK) return status;

#ifdef DEBUG1
    ice_media_utils_dump_cand_pair_stats(media);
#endif

    /** sec 5.7.2 ordering pairs */
    status = ice_media_utils_sort_candidate_pairs(media);
    if (status != STUN_OK) return status;

#ifdef DEBUG1
    ice_media_utils_dump_cand_pair_stats(media);
#endif

    /** sec 5.7.3 pruning the pairs */
    status = ice_media_utils_prune_checklist(media);
    if (status != STUN_OK) return status;

    /** sec 5.7.4 computing states */
    status = ice_media_utils_compute_initial_states_for_pairs(media);
    if (status != STUN_OK) return status;

#ifdef DEBUG
    ice_media_utils_dump_cand_pair_stats(media);
#endif


    /**
     * RFC 5245 Sec 7.2 STUN Server Procedures
     * It is possible (and in fact very likely) that an offerer will receive 
     * a Binding request prior to receiving the answer from its peer. Once the 
     * answer is received, it MUST proceed with the remaining steps required, 
     * namely, 7.2.1.3, 7.2.1.4, and 7.2.1.5 for full implementations. 
     */
    if (media->ic_check_count > 0)
    {
        status = ice_utils_process_pending_ic_checks(media);
    }

    /** 
     * initially when the checklist is formed, 
     * the media checklist is in frozen state 
     */
    media->state = ICE_MEDIA_FROZEN;

    return STUN_OK;
}


int32_t ice_media_unfreeze(ice_media_stream_t *media, handle h_msg)
{
    int32_t status;
    ice_cand_pair_t *pair;

    if (media->ice_session->use_relay == true)
    {
        /**
         * Before the connectivity checks are initiated for this media,
         * install permissions on the turn server in case the session
         * is making use of turn relay.
         */
        status = ice_utils_install_turn_permissions(media);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "[ICE MEDIA] Installing of TURN permissions failed");
            return status;
        }
    }

    /** 
     * The checklist for this media is now active. The initial check 
     * is always an ordinary check and is sent out immediately after 
     * the offer-answer exchange.
     * connectivity check timer for the active check list is started.
     * Note: as of now we support only one media, hence only one 
     *       check list.
     */

    /** set the initial state of the candidate pairs */
    status = ice_media_utils_initialize_cand_pairs(media);
    if (status != STUN_OK) return status;

#ifdef DEBUG
    ice_media_utils_dump_cand_pair_stats(media);
#endif

    status = ice_media_utils_get_next_connectivity_check_pair(media, &pair);
    if (status != STUN_OK) return status;

    status = ice_cand_pair_fsm_inject_msg(pair, ICE_CP_EVENT_INIT_CHECK, NULL);
    /** TODO - check the return value of candidate pair fsm???? */

    /** as soon as we have sent out the first conn check, move the state */
    media->state = ICE_MEDIA_CC_RUNNING;

    /** allocate memory for conn checka timer params */
    media->checklist_timer = (ice_timer_params_t *) 
                stun_calloc (1, sizeof(ice_timer_params_t));
    if (media->checklist_timer == NULL)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE MEDIA] Memory allocation failed for ICE conn "\
                "check timer");
        return STUN_NO_RESOURCE;
    }
    media->checklist_timer->timer_id = 0;

    status = ice_media_utils_start_check_list_timer(media);

    /** 
     * start the connectivity checks timeout timer as well. This timer 
     * will decide as to when this agent stops the connectivity checks
     * and evaluates the valid pairs. This timer is only applicable
     * when the agent's role is CONTROLLING for the session.
     */
    if ((media->ice_session->role == ICE_AGENT_ROLE_CONTROLLING) &&
        (media->ice_session->instance->nomination_mode == ICE_NOMINATION_TYPE_REGULAR))
    {
        media->nomination_timer = (ice_timer_params_t *) 
                    stun_calloc (1, sizeof(ice_timer_params_t));
        if (media->nomination_timer == NULL)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "[ICE MEDIA] Memory allocation failed for ICE conn "\
                    "check nomination timer");
            return STUN_NO_RESOURCE;
        }

        status = ice_media_utils_start_nomination_timer(media);
    }

    return status;
}



int32_t ice_media_process_rx_msg(ice_media_stream_t *media, handle pkt)
{
    int32_t status;
    handle h_cc_inst, h_cc_dialog;
    ice_rx_stun_pkt_t *stun_pkt = (ice_rx_stun_pkt_t *) pkt;

    h_cc_inst = media->ice_session->instance->h_cc_inst;

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE MEDIA] Received message from %s and port %d", 
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
                    "[ICE MEDIA] Discarding the stray stun "\
                    "response/indication message");

            stun_msg_destroy(stun_pkt->h_msg);
            return STUN_OK;
        }

        /** create new incoming connectivity check dialog */
        status = ice_utils_create_conn_check_session(media, stun_pkt);
        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                "[ICE MEDIA] ice_utils_create_conn_check_session() "\
                "returned error %d\n", status);
            return STUN_INT_ERROR;
        }

        status = conn_check_session_inject_received_msg(
                        h_cc_inst, media->h_cc_svr_session, stun_pkt->h_msg);
        if (status == STUN_TERMINATED)
        {
            ice_candidate_t *local;
            conn_check_result_t check_result;

            status = conn_check_session_get_check_result(
                                h_cc_inst, media->h_cc_svr_session, &check_result);
            if (status != STUN_OK) return status;

    
            /** RFC 5245 sec 7.2.1.1 Detecting and Repairing Role Conflicts */
            ice_utils_check_for_role_change(media, &check_result);

            local = ice_utils_get_local_cand_for_transport_param(
                                            media, stun_pkt->transport_param);

            /**
             * RFC 5245 sec 7.2 STUN Server Procedures
             * It is possible (and in fact very likely) that an offerer 
             * will receive a Binding request prior to receiving the 
             * answer from its peer. If this happens, then add this pair 
             * to the triggered check queue. Once the answer is received 
             * from the peer, this pair will be handled. 
             */
            if (media->state == ICE_MEDIA_GATHERED)
            {
                status = ice_utils_add_to_ic_check_queue_without_answer(
                                   media, local, &check_result, &stun_pkt->src);

                conn_check_destroy_session(h_cc_inst, media->h_cc_svr_session);
                media->h_cc_svr_session = NULL;

                return status;
            }


            /** if we are here, then answer has been received */
            status = ice_utils_process_incoming_check(
                                    media, local, stun_pkt, &check_result);

            conn_check_destroy_session(h_cc_inst, media->h_cc_svr_session);
            media->h_cc_svr_session = NULL;
        }
        else if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                "[ICE MEDIA] conn_check_session_inject_received_msg() "\
                "returned error %d. Incoming conn check req discarded\n", 
                status);

            conn_check_destroy_session(h_cc_inst, media->h_cc_svr_session);
            media->h_cc_svr_session = NULL;
            return STUN_INT_ERROR;
        }
    }
    else if (status == STUN_OK)
    {
        status = ice_utils_process_conn_check_response(
                                media, stun_pkt, h_cc_inst, h_cc_dialog);
    }

    return status;
}




int32_t ice_media_stream_checklist_timer_expiry(
                                ice_media_stream_t *media, handle arg)
{
    int32_t status;
    ice_cand_pair_t *pair;

    ice_media_utils_dump_cand_pair_stats(media);

    media->checklist_timer->timer_id = 0;

    status = ice_media_utils_get_next_connectivity_check_pair(media, &pair);
    if (status == STUN_OK)
    {
        /** If the pair is frozen, then unfreeze before initiating the check */
        if ((pair->state == ICE_CP_FROZEN) || (pair->state == ICE_CP_SUCCEEDED))
            status = ice_cand_pair_fsm_inject_msg(
                                        pair, ICE_CP_EVENT_UNFREEZE, NULL);

        status = ice_cand_pair_fsm_inject_msg(pair, 
                                        ICE_CP_EVENT_INIT_CHECK, NULL);

        /** restart the timer */
        if (status == STUN_OK)
            status = ice_media_utils_start_check_list_timer(media);
    }
    else if (status == STUN_NOT_FOUND)
    {
        /**
         * RFC 5245 sec 5.8 Scheduling Checks
         * No more pairs available for connectivity checks.
         * Hence terminate the check list timer
         */
        status = STUN_OK;

        /** TODO
         * 1. what should be the return value from this function?
         * 2. Should the media state be changed to COMPLETED?
         */
    }
    else
    {
        ICE_LOG(LOG_SEV_ERROR,
                "Unable to determine the candidate pair for "\
                "the next connectivity check %d", status);
    }

    return status;
}



int32_t ice_media_stream_evaluate_valid_pairs(
                                    ice_media_stream_t *media, handle arg)
{
    int32_t count, status;
    ice_cand_pair_t *np;

    ICE_LOG(LOG_SEV_INFO,
            "Nomination timer expired. Time to evaluate the candidate pairs "\
            "in valid list and nominate one of them for media %p", media);

    media->nomination_timer->timer_id = 0;

    /**
     * RFC 5245 sec 8.1.1.1 Regular Nomination
     */
    
    /** make sure we have valid pairs for all the components */
    if(ice_media_utils_have_valid_list(media) == false)
    {
        /** 
         * No valid pairs for one or more components for this media
         * so far. That is, the connectivity checks have failed to 
         * generate any valid pairs for this media. Hence moving 
         * the state of the media stream to Failed.
         */

        /** TODO =
         * 1. Stop checklist timer if running.
         * 2. stop any conn check re-transmission?
         */

        media->state = ICE_MEDIA_CC_FAILED;

        return STUN_OK;
    }

    /** This media has atleast one nominated pair for each of it's components */

    for (count = 0; count < media->num_comp; count++)
    {
        np = ice_utils_select_nominated_cand_pair(media, (count + 1));
        
        /** 
         * no need for return value check since we have already verified 
         * availability of the nominated pair for each component 
         */

        /*
         * When the controlling agent selects the valid pair, it repeats the
         * check that produced this valid pair (by enqueuing the pair that
         * generated the check into the triggered check queue), this time with
         * the USE-CANDIDATE attribute.
         */

        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Candidate pair %p current state %d", 
                np, np->state);

        np->check_nom_status = true;

        status = ice_utils_add_to_triggered_check_queue(media, np);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "[ICE MEDIA] Adding of nominated candidate pair %p for "\
                    "component %d to triggered list for media %p failed", 
                    np, (count + 1), media);
            
            media->state = ICE_MEDIA_CC_FAILED;

            return STUN_INT_ERROR;
        }

        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Added nominated candidate pair %p for component "\
                "%d to triggered list for media %p", np, (count + 1), media);
    }

    /** 
     * make sure the checklist timer is running. If stopped, 
     * then restart it so that the nominated triggered checks
     * that we have added above are processed 
     */
    if (media->checklist_timer->timer_id == 0)
    {
        status = ice_media_utils_start_check_list_timer(media);
    }

    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_INFO,
                "[ICE MEDIA] Unable to start the checklist timer after adding"\
                " the nominated pairs to triggered queue for media %p", media);
    }
    else
    {
        media->state = ICE_MEDIA_NOMINATING;
    }

    return status;
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
            "[ICE MEDIA] Setting of remote params failed for media %p", media);
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
            "[ICE MEDIA] Forming of candidates failed for media %p", media);
        return status;
    }

    status = ice_utils_dual_lite_select_valid_pairs(media);

    return status;
}



int32_t ice_media_conn_check_timer_expiry(
                            ice_media_stream_t *media, handle h_msg)
{
    int32_t status;
    handle h_cc_dialog, h_cc_inst;
    ice_timer_params_t *timer = (ice_timer_params_t *) h_msg;

    status = conn_check_instance_inject_timer_event(
                                timer->timer_id, timer->arg, &h_cc_dialog);
    if (status == STUN_TERMINATED)
    {
        ice_cand_pair_t *cp = NULL;
        conn_check_result_t check_result;

        ICE_LOG(LOG_SEV_INFO, 
                "[ICE MEDIA] Conn check sesssion terminated due to timeout");

        /** 
         * connectivity check terminated. Retrieve the overall
         * result of the connectivity check and feed it to the 
         * corresponding cand pair fsm. Then destroy the 
         * connectivity check session if no longer required.
         */
        status = ice_utils_find_cand_pair_for_conn_check_session(
                                                media, h_cc_dialog, &cp);
        if (status == STUN_OK)
        {
            h_cc_inst = media->ice_session->instance->h_cc_inst;
            status = conn_check_session_get_check_result(
                                h_cc_inst, h_cc_dialog, &check_result);

            if (check_result.check_succeeded == true)
            {
                ICE_LOG(LOG_SEV_INFO, 
                        "[ICE MEDIA] Conn check sesssion succeeded on "\
                        "termination. This is unexpected and illogical");
                status = STUN_INT_ERROR;
            }
            else
            {
                status = ice_cand_pair_fsm_inject_msg(
                        cp, ICE_CP_EVENT_CHECK_FAILED, &check_result);

                if (ice_media_utils_did_all_checks_fail(media) == true)
                {
                    /** all checks have failed */
                    media->state = ICE_MEDIA_CC_FAILED;
                }
            }

            status = conn_check_destroy_session(h_cc_inst, h_cc_dialog);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, 
                        "Destroying of connectivity check session "\
                        "failed %d", status);
            }

            cp->h_cc_session = NULL;
        }
        else
        {
            ICE_LOG(LOG_SEV_INFO, 
                    "[ICE MEDIA] Conn check sesssion terminated");
        }

        ice_media_utils_dump_cand_pair_stats(media);
    }

    return status;
}



int32_t ice_media_stream_keep_alive_timer_expiry(
                                ice_media_stream_t *media, handle arg)
{
    int32_t i, status = STUN_OK;
    ice_timer_params_t *timer = (ice_timer_params_t *) arg;
    ice_cand_pair_t *np = NULL;

    /** find the nominated pair for the component */
    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->media_comps[i].comp_id == (uint32_t) timer->arg)
        {
            np = media->media_comps[i].np;
            break;
        }
    }

    if (np == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE MEDIA] Keep Alive timer expired. Unable to find the "\
                "nominated pair for the component ID %d", (uint32_t)timer->arg);
        return STUN_INT_ERROR;
    }


    /** 
     * if the nominated pair is a relayed candidate pair, then the
     * ICE layer need not keep the NAT binding alive. The TURN layer
     * anyway refreshes the NAT bindings for the communication path
     * between the endpoint and the relay/turn server by sending empty
     * SEND indications. Sending a BINDING indication will unnecessarily
     * increase the bandwidth.
     */

    if (np->local->type != ICE_CAND_TYPE_RELAYED)
    {
        /** send binding indication to the nominated pair */
        status = ice_media_utils_send_keepalive_msg(media, np);
    }

    /** no change in state */

    /** (re)start the keep alive timer for the component */
    status = ice_utils_start_keep_alive_timer_for_comp(
                                        media, np->local->comp_id);

    return status;
}



int32_t ice_media_stream_send_data(ice_media_stream_t *media, handle arg)
{
    int32_t i, status = STUN_OK;
    ice_media_data_t *data_params = (ice_media_data_t *) arg;
    ice_cand_pair_t *np = NULL;

    /** find the nominated pair for the component */
    for (i = 0; i < ICE_MAX_COMPONENTS; i++)
    {
        if (media->media_comps[i].comp_id == data_params->comp_id)
        {
            np = media->media_comps[i].np;
            break;
        }
    }

    if (np == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[ICE MEDIA] Nominated pair not found for component id %d.", 
                data_params->comp_id);
        return STUN_INVALID_PARAMS;
    }


    /** 
     * if the nominated pair is a relayed candidate pair, then pass on the 
     * data to the TURN module. Else send the data directly via the callback.
     */

    if (np->local->type == ICE_CAND_TYPE_RELAYED)
    {
        stun_inet_addr_t dest;

        /** 
         * Currently transport type is not being made use of and 
         * passed on to the TURN module. It's better if TURN layer 
         * makes use of the transport type as it would help support 
         * of TCP and any other protocols in future. That would avoid
         * the data conversion between data structures as below  - TODO.
         */
        dest.host_type = np->remote->transport.type;
        stun_strncpy((char *)dest.ip_addr, 
                (char *)np->remote->transport.ip_addr, ICE_IP_ADDR_MAX_LEN);
        dest.port = np->remote->transport.port;

        /** finding the turn session handle this way is not clean! */
        status = turn_session_send_application_data(
                media->ice_session->instance->h_turn_inst, 
                media->h_turn_sessions[data_params->comp_id], 
                &dest, data_params->data, data_params->len);
    }
    else
    {
        status = media->ice_session->instance->nwk_send_cb(
                    data_params->data, data_params->len, 
                    np->remote->transport.type, np->remote->transport.ip_addr, 
                    np->remote->transport.port, np->local->transport_param);
    }

    /** no change in state */

    return status;
}



int32_t ice_media_stream_ignore_msg(ice_media_stream_t *media, handle h_msg)
{
    ICE_LOG(LOG_SEV_ERROR, "[ICE MEDIA] Event ignored");
    return STUN_OK;
}



int32_t ice_media_stream_fsm_inject_msg(ice_media_stream_t *media, 
                                ice_media_stream_event_t event, handle h_msg)
{
    int32_t status;
    ice_media_stream_state_t cur_state;
    ice_media_stream_fsm_handler handler;

    ICE_LOG(LOG_SEV_INFO, 
            "[ICE MEDIA] Processing event %d in %d state", event, media->state);

    cur_state = media->state;
    handler = ice_media_stream_fsm[cur_state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(media, h_msg);

    if (cur_state != media->state)
    {
        ice_media_utils_notify_state_change_event(media);
    }

    if (media->o_removed == true)
        ice_media_utils_clear_media_stream(media);

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
