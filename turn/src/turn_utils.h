/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2011, MindBricks Technologies               *
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

#ifndef TURN_UTILS__H
#define TURN_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

int32_t turn_utils_create_request_msg(turn_session_t *session, 
                                    stun_method_type_t method, handle *h_msg);

int32_t turn_utils_create_indication(handle *h_msg);

int32_t turn_utils_create_response_msg(handle *h_inst);

int32_t turn_utils_cache_auth_params(turn_session_t *session, handle h_msg);

int32_t turn_utils_create_alloc_req_msg_with_credential(
                            turn_session_t *session, handle *h_newmsg);

int32_t turn_utils_create_dealloc_req_msg(
                            turn_session_t *session, handle *h_newmsg);

int32_t turn_utils_get_app_data_for_current_state(
                                turn_session_t *session, handle *data);

int32_t turn_utils_extract_data_from_alloc_resp(
                                turn_session_t *session, handle h_msg);

int32_t turn_utils_extract_data_from_refresh_resp(
                                turn_session_t *session, handle h_msg);

int32_t turn_utils_create_refresh_req_msg(
                            turn_session_t *session, handle *h_newmsg);

int32_t turn_utils_create_permission_req_msg(
                            turn_session_t *session, handle *h_newmsg);

int32_t turn_utils_create_send_ind_msg(
        turn_session_t *session, turn_app_data_t *data, handle *h_newmsg);

int32_t turn_utils_process_data_indication(
                                turn_session_t *session, handle h_msg);

int32_t turn_session_utils_notify_state_change_event(turn_session_t *session);

int32_t turn_utils_start_alloc_refresh_timer(
                                turn_session_t *session, uint32_t duration);

int32_t turn_utils_stop_alloc_refresh_timer(turn_session_t *session);

int32_t turn_utils_start_perm_refresh_timer(
                                turn_session_t *session, uint32_t duration);

int32_t turn_utils_stop_perm_refresh_timer(turn_session_t *session);

int32_t turn_utils_start_keep_alive_timer(
                                turn_session_t *session, uint32_t duration);

int32_t turn_utils_stop_keep_alive_timer(turn_session_t *session);

int32_t turn_table_validate_session_handle(handle h_inst, handle h_session);

void turn_utils_free_all_session_timers(turn_session_t *session);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
