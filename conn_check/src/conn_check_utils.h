/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Copyright (C) 2009-2012, Rajmohan Banavi                    *
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

#ifndef CONN_CHECK_UTILS__H
#define CONN_CHECK_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



int32_t cc_utils_create_request_msg(
                            conn_check_session_t *session, handle *h_req);

int32_t cc_utils_create_indication(handle *h_msg);

int32_t cc_utils_create_response_msg(handle *h_inst);

int32_t conn_check_utils_get_app_data_for_current_state(
                                conn_check_session_t *session, handle *data);

int32_t cc_utils_create_resp_from_req(conn_check_session_t *session,
                     handle h_req, stun_msg_type_t msg_type, handle *h_resp);

int32_t conn_check_utils_verify_request_msg(
                    conn_check_session_t *session, handle h_msg);

int32_t conn_check_utils_extract_info_from_request_msg(
                conn_check_session_t *session, handle h_msg);

int32_t conn_check_utils_send_error_resp(
                                conn_check_session_t *session, 
                                uint32_t error_code, char *reason);

int32_t conn_check_utils_extract_username_components(
                u_char *username, uint32_t len, u_char **local_user, 
                uint32_t *local_len, u_char **peer_user, uint32_t *peer_len);

int32_t cc_utils_extract_error_code(handle h_msg, uint32_t *error_code);

uint32_t cc_utils_extract_conn_check_info(handle h_msg, 
                                            conn_check_session_t *session);

int32_t conn_check_detect_repair_role_conflicts(
        conn_check_session_t *session, handle h_msg, int32_t *resp_code);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
