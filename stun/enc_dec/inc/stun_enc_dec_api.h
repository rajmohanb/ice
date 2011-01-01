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

#ifndef STUN_ENC_DEC_API__H
#define STUN_ENC_DEC_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"


#define STUN_MSG_AUTH_PASSWORD_LEN  128

typedef struct 
{
    uint32_t len;
    u_char password[STUN_MSG_AUTH_PASSWORD_LEN];
} stun_auth_params_t;

/**
 * Parse api. Parses the given TLV message into message structure and returns
 * the same. Further operations like set and get can be done on this returned
 * h_msg
 */
int32_t stun_msg_decode(u_char *buf, uint32_t len, handle *tlv);

/**
 * Format api. Converts the given message to TLV format and returns the TLV
 * message that can be sent on the network
 */
int32_t stun_msg_encode(handle tlv, 
            stun_auth_params_t *auth, u_char *buf, uint32_t *size);


int32_t stun_msg_print (handle stun_msg, u_char *buf, uint32_t buf_len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
