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

#ifndef STUN_TXN_UTILS__H
#define STUN_TXN_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t stun_txn_utils_generate_txn_id(u_char *txn_id, uint32_t bytes);


int32_t stun_txn_utils_killall_timers (stun_txn_context_t *txn_ctxt);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
