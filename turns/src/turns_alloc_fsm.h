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

int32_t turns_ignore_msg (turns_allocation_t *alloc, handle h_msg);

int32_t turns_allocation_fsm_inject_msg(turns_allocation_t *alloc, 
                                    turns_alloc_event_t event, handle h_msg);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
