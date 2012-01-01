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

#ifndef ICE_CAND_PAIR_FSM__H
#define ICE_CAND_PAIR_FSM__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



int32_t ice_cp_unfreeze(ice_cand_pair_t *cp, handle h_msg);


int32_t ice_cp_initiate_check(ice_cand_pair_t *cp, handle h_msg);


int32_t ice_cp_check_succeeded(ice_cand_pair_t *cp, handle h_msg);


int32_t ice_cp_check_failed(ice_cand_pair_t *cp, handle h_msg);


int32_t ice_cp_ignore_msg(ice_cand_pair_t *cp, handle h_msg);


int32_t ice_cand_pair_fsm_inject_msg(ice_cand_pair_t *cp, 
                                    ice_cp_event_t event, handle h_msg);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
