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

#ifndef STUN_ENC_DEC_UTILS__H
#define STUN_ENC_DEC_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

int32_t stun_tlv_utils_get_hmac_key(handle h_msg, u_char *key);

uint16_t stun_tlv_utils_get_stun_msg_type(stun_msg_t *msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
