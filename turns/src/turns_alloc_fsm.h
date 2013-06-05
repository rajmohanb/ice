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


int32_t turns_process_alloc_req (turns_allocation_t *alloc, handle h_msg);


int32_t turns_alloc_accepted (turns_allocation_t *alloc, handle h_msg);


int32_t turns_alloc_rejected (turns_allocation_t *alloc, handle h_msg);


int32_t turns_refresh_req (turns_allocation_t *alloc, handle h_msg);


int32_t turns_send_ind (turns_allocation_t *alloc, handle h_msg);


int32_t turns_channel_data_ind (turns_allocation_t *alloc, handle h_msg);


int32_t turns_process_alloc_timer (turns_allocation_t *alloc, handle h_msg);


int32_t turns_perm_timer (turns_allocation_t *alloc, handle h_msg);


int32_t turns_channel_bind_timer (turns_allocation_t *alloc, handle h_msg);


int32_t turns_generate_new_nonce(turns_allocation_t *alloc, handle h_msg);


int32_t turns_create_perm_req(turns_allocation_t *alloc, handle h_msg);


int32_t turns_channel_bind_req(turns_allocation_t *alloc, handle h_msg);


int32_t turns_media_data (turns_allocation_t *alloc, handle h_msg);


int32_t turns_terminate_allocation (turns_allocation_t *alloc, handle h_msg);


int32_t turns_ignore_msg (turns_allocation_t *alloc, handle h_msg);


int32_t turns_allocation_fsm_inject_msg(turns_allocation_t *alloc, 
                                    turns_alloc_event_t event, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
