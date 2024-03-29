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

#ifndef TURN_SESSION_FSM__H
#define TURN_SESSION_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t send_alloc_req (turn_session_t *session, handle h_msg);

int32_t process_alloc_resp (turn_session_t *session, handle h_msg);

int32_t turn_allocation_timeout (turn_session_t *session, handle h_msg);

int32_t send_perm_req (turn_session_t *session, handle h_msg);

int32_t process_perm_resp (turn_session_t *session, handle h_msg);

int32_t turn_init_dealloc (turn_session_t *session, handle h_msg);

int32_t turn_refresh_resp (turn_session_t *session, handle h_rcvdmsg);

int32_t turn_dealloc_resp (turn_session_t *session, handle h_rcvdmsg);

int32_t turn_refresh_allocation (turn_session_t *session, handle h_msg);

int32_t turn_send_ind(turn_session_t *session, handle h_msg);

int32_t turn_data_ind(turn_session_t *session, handle h_msg);

int32_t turn_refresh_permission (turn_session_t *session, handle h_msg);

int32_t turn_refresh_channel_binding (turn_session_t *session, handle h_msg);

int32_t turn_refresh_nat_binding (turn_session_t *session, handle h_msg);

int32_t turn_ignore_msg (turn_session_t *session, handle h_msg);

int32_t turn_session_fsm_inject_msg(turn_session_t *session, 
                                    turn_event_t event, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
