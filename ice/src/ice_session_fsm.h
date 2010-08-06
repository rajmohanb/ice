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

#ifndef ICE_SESSION_FSM__H
#define ICE_SESSION_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t gather_candidates(ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t handle_gather_result(ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t process_relay_server_msg (ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t ice_form_checklist(ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t initiate_checks(ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t handle_peer_msg (ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t ice_nominate(ice_session_t *session, handle h_msg, handle *h_param);

int32_t ice_completed(ice_session_t *session, handle h_msg, handle *h_param);

int32_t ice_handle_checklist_timer_expiry(ice_session_t *session, 
                                                handle arg, handle *h_param);

int32_t ice_restart (ice_session_t *session, handle arg, handle *h_param);

int32_t ice_remote_params (ice_session_t *session, handle arg, handle *h_param);

int32_t ice_add_media_stream (ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t ice_remove_media_stream (ice_session_t *session, 
                                            handle h_msg, handle *h_param);

int32_t ice_ignore_msg (ice_session_t *session, handle h_msg, handle *h_param);

int32_t ice_session_fsm_inject_msg(ice_session_t *session, 
                ice_session_event_t event, handle h_msg, handle *h_param);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
