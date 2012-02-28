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

#ifndef CONN_CHECK_SESSION_FSM__H
#define CONN_CHECK_SESSION_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t cc_initiate (conn_check_session_t *session, handle h_msg);

int32_t cc_process_ic_check (conn_check_session_t *session, handle h_msg);

int32_t cc_handle_resp (conn_check_session_t *session, handle h_rcvdmsg);

int32_t cc_timeout (conn_check_session_t *session, handle h_rcvdmsg);

int32_t cc_ignore_event (conn_check_session_t *session, handle h_msg);

int32_t conn_check_session_fsm_inject_msg(
                                    conn_check_session_t *session, 
                                    conn_check_event_t event, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
