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

#ifndef ICE_UTILS__H
#define ICE_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

uint64_t ice_utils_compute_priority(ice_candidate_t *cand);

int32_t ice_utils_compute_foundation(ice_candidate_t *cand);

int32_t ice_media_utils_form_candidate_pairs(ice_media_stream_t *media);

int32_t ice_utils_compute_candidate_pair_priority(
            ice_session_t *session, ice_cand_pair_t *cand_pair);

int32_t ice_utils_get_next_connectivity_check_pair(
        ice_media_stream_t *media, ice_cand_pair_t **pair);

int32_t ice_utils_copy_media_host_candidates(
                ice_api_media_stream_t *src, ice_media_stream_t *dest);

int32_t ice_utils_find_session_for_transport_handle(
    ice_instance_t *instance, handle transport_param, handle *h_session);

ice_media_stream_t *
    ice_session_utils_find_media_stream_for_turn_handle(
                    ice_session_t *ice_session, handle h_turn_handle);


void ice_utils_compute_foundation_ids(ice_media_stream_t *media);

handle ice_media_utils_get_base_cand_for_comp_id(
                            ice_media_stream_t *media, uint32_t comp_id);

int32_t ice_utils_find_media_for_transport_handle(
    ice_session_t *session, handle transport_param, int32_t *index);

void ice_media_utils_dump_cand_pair_stats(ice_media_stream_t *media);

int32_t ice_utils_create_conn_check_session(
                    ice_media_stream_t *media, ice_rx_stun_pkt_t *pkt);

void ice_utils_dump_media_params(ice_media_params_t *media_params);

ice_candidate_t *ice_utils_get_local_cand_for_transport_param(
                ice_media_stream_t *media, handle transport_param);

ice_candidate_t *ice_utils_get_peer_cand_for_pkt_src(
                    ice_media_stream_t *media, stun_inet_addr_t *src);

bool_t ice_media_utils_have_valid_list(ice_media_stream_t *media);

int32_t ice_media_utils_copy_selected_pair(ice_media_stream_t *media);

int32_t ice_utils_get_session_state_change_event(
                    ice_session_t *session, ice_state_t *event);

int32_t ice_utils_get_media_state_change_event(
                    ice_media_stream_t *media, ice_state_t *event);

int32_t ice_media_utils_notify_state_change_event(
                                        ice_media_stream_t *media);

int32_t ice_session_utils_notify_state_change_event(
                                            ice_session_t *session);

int32_t ice_utils_get_local_media_params(
        ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_utils_set_peer_media_params(
        ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_media_utils_get_valid_list(ice_media_stream_t *media, 
                                    ice_media_valid_pairs_t *valid_pairs);

int32_t ice_utils_get_media_params_in_running_state(
            ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_utils_get_nominated_valid_pair(
        ice_media_stream_t *media, uint32_t comp_id, ice_cand_pair_t **nom_pair);

int32_t ice_utils_get_highest_priority_nominated_valid_pair(
        ice_media_stream_t *media, uint32_t comp_id, ice_cand_pair_t **nom_pair);

int32_t ice_utils_get_media_params_in_completed_state(
            ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_utils_determine_session_state(ice_session_t *session);

int32_t ice_utils_dual_lite_select_valid_pairs(ice_media_stream_t *media);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
