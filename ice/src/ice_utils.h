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

uint64_t ice_utils_compute_candidate_priority(ice_candidate_t *cand);

uint64_t ice_utils_compute_peer_reflexive_candidate_priority(
                                                    ice_candidate_t *cand);

int32_t ice_utils_compute_candidate_foundation(ice_candidate_t *cand);

int32_t ice_media_utils_form_candidate_pairs(ice_media_stream_t *media);

int32_t ice_utils_compute_candidate_pair_priority(
            ice_session_t *session, ice_cand_pair_t *cand_pair);

int32_t ice_media_utils_sort_candidate_pairs(ice_media_stream_t *media);

int32_t ice_media_utils_prune_checklist(ice_media_stream_t *media);

int32_t ice_media_utils_compute_initial_states_for_pairs(
                                            ice_media_stream_t *media);

int32_t ice_utils_get_next_connectivity_check_pair(
        ice_media_stream_t *media, ice_cand_pair_t **pair);

int32_t ice_utils_nominate_candidate_pair(
        ice_session_t *session, ice_cand_pair_t *pair);

int32_t ice_utils_copy_media_host_candidates(
                ice_api_media_stream_t *src, ice_media_stream_t *dest);

int32_t ice_utils_find_session_for_transport_handle(
    ice_instance_t *instance, handle transport_param, handle *h_session);

ice_media_stream_t *
    ice_session_utils_find_media_stream_for_turn_handle(
                    ice_session_t *ice_session, handle h_turn_handle);


void ice_utils_compute_foundation_ids(ice_media_stream_t *media);

int32_t ice_media_utils_initialize_cand_pairs(ice_media_stream_t *media);

handle ice_media_utils_get_base_cand_for_comp_id(
                            ice_media_stream_t *media, uint32_t comp_id);

uint32_t ice_utils_get_conn_check_timer_duration(ice_media_stream_t *media);

int32_t ice_utils_find_media_for_transport_handle(
    ice_session_t *session, handle transport_param, int32_t *index);

void ice_media_utils_dump_cand_pair_stats(ice_media_stream_t *media);

int32_t ice_utils_create_conn_check_session(
                    ice_media_stream_t *media, ice_rx_stun_pkt_t *pkt);

int32_t ice_media_utils_get_next_connectivity_check_pair(
        ice_media_stream_t *media, ice_cand_pair_t **pair);

void ice_utils_dump_media_params(ice_media_params_t *media_params);

ice_candidate_t *ice_utils_get_local_cand_for_transport_param(
                ice_media_stream_t *media, handle transport_param);

handle ice_utils_get_turn_session_for_transport_param(
                    ice_media_stream_t *media, handle transport_param);

ice_candidate_t *ice_utils_get_peer_cand_for_pkt_src(
                    ice_media_stream_t *media, stun_inet_addr_t *src);

bool_t ice_media_utils_have_nominated_list(ice_media_stream_t *media);

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

int32_t ice_media_utils_get_nominated_list(ice_media_stream_t *media, 
                                    ice_media_valid_pairs_t *valid_pairs);

int32_t ice_utils_get_media_params_in_running_state(
            ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_utils_get_nominated_valid_pair(
                            ice_media_stream_t *media, uint32_t comp_id, 
                            ice_cand_pair_t **nom_pair);

int32_t ice_utils_get_highest_priority_nominated_valid_pair(
                            ice_media_stream_t *media, uint32_t comp_id, 
                            ice_cand_pair_t **nom_pair);

int32_t ice_utils_get_media_params_in_completed_state(
            ice_media_stream_t *media, ice_media_params_t *media_params);

int32_t ice_utils_determine_session_state(ice_session_t *session);

int32_t ice_utils_dual_lite_select_valid_pairs(ice_media_stream_t *media);

int32_t ice_utils_validate_turn_session_handle(
        ice_media_stream_t *media, handle h_turn_session, uint32_t *comp_id);

int32_t ice_utils_get_free_local_candidate(
                        ice_media_stream_t *media, ice_candidate_t **cand);

int32_t ice_utils_copy_gathered_candidate_info(ice_candidate_t *cand, 
                                stun_inet_addr_t *alloc_addr, 
                                ice_cand_type_t cand_type, uint32_t comp_id,
                                ice_candidate_t *base_cand);

int32_t ice_utils_copy_turn_gathered_candidates(
        ice_media_stream_t *media, ice_int_params_t *param, uint32_t comp_id);

int32_t ice_media_utils_start_check_list_timer(ice_media_stream_t *media);

int32_t ice_media_utils_start_nomination_timer(ice_media_stream_t *media);

int32_t ice_cand_pair_utils_init_connectivity_check(ice_cand_pair_t *pair);

int32_t ice_utils_find_cand_pair_for_conn_check_session(
        ice_media_stream_t *media, handle h_conn_check, ice_cand_pair_t **cp);

void ice_utils_handle_agent_role_conflict(
                ice_media_stream_t *media, ice_agent_role_type_t new_role);

int32_t ice_utils_search_local_candidates(ice_media_stream_t *media, 
                    conn_check_result_t *check, ice_candidate_t **found_cand);

int32_t ice_utils_add_local_peer_reflexive_candidate(ice_cand_pair_t *cp, 
                    conn_check_result_t *check, ice_candidate_t **new_prflx);

int32_t ice_utils_add_to_valid_list(ice_media_stream_t *media, 
        ice_candidate_t *local_cand, ice_rx_stun_pkt_t *pkt, bool_t nominated);

int32_t ice_utils_install_turn_permissions(ice_media_stream_t *media);

int32_t ice_media_utils_update_cand_pair_states(
                        ice_media_stream_t *media, ice_cand_pair_t *cur_cp);

int32_t ice_utils_detect_repair_role_conflicts(
                    ice_media_stream_t *media, ice_rx_stun_pkt_t *stun_pkt);

ice_cand_pair_t *ice_utils_lookup_pair_in_checklist(
                            ice_media_stream_t *media, ice_candidate_t *local, 
                            ice_candidate_t *remote);

int32_t ice_utils_add_to_triggered_check_queue(
                            ice_media_stream_t *media, ice_cand_pair_t *cp);

int32_t ice_utils_search_remote_candidates(ice_media_stream_t *media, 
                    stun_inet_addr_t *pkt_src, ice_candidate_t **found_cand);

int32_t ice_utils_add_to_ic_check_queue_without_answer(
                ice_media_stream_t *media, ice_candidate_t *local, 
                conn_check_result_t *check_info, stun_inet_addr_t *remote);

int32_t ice_utils_process_pending_ic_checks(ice_media_stream_t *media);

int32_t ice_utils_add_remote_peer_reflexive_candidate(
                        ice_media_stream_t *media, stun_inet_addr_t *peer_addr,
                        uint32_t prflx_comp_id, uint32_t prflx_priority, 
                        ice_candidate_t **new_prflx);

int32_t ice_media_utils_add_new_candidate_pair(ice_media_stream_t *media, 
        ice_candidate_t *local, ice_candidate_t *remote, ice_cand_pair_t **cp);

int32_t ice_utils_process_incoming_check(
                ice_media_stream_t *media, ice_candidate_t *local_cand, 
                ice_rx_stun_pkt_t *stun_pkt, conn_check_result_t *check_result);

ice_cand_pair_t *ice_utils_search_cand_pair_in_valid_pair_list(
                                ice_media_stream_t *media, ice_cand_pair_t *cp);

int32_t ice_utils_update_media_checklist_state(
                    ice_media_stream_t *media, ice_cand_pair_t *valid_pair);

uint32_t ice_utils_get_nominated_pairs_count(ice_media_stream_t *media);

int32_t ice_media_utils_stop_checks_for_comp_id(
                            ice_media_stream_t *media, uint32_t comp_id);

void ice_utils_remove_from_triggered_check_queue(
                        ice_media_stream_t *media, ice_cand_pair_t *cp);

bool_t ice_media_utils_have_valid_list(ice_media_stream_t *media);

ice_cand_pair_t *ice_utils_select_nominated_cand_pair(
                                ice_media_stream_t *media, uint32_t comp_id);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
