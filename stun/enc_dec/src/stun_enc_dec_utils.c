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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include <netinet/in.h>

#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_enc_dec_api.h"
#include "stun_enc_dec_int.h"
#include "stun_attr_enc_dec.h"

#include <openssl/md5.h>

/*============================================================================*/

#define STUN_BINDING_REQ            0x0001
#define STUN_BINDING_IND            0x0011
#define STUN_BINDING_SUCCESS_RESP   0x0101
#define STUN_BINDING_ERROR_RESP     0x0111

#define STUN_ALLOCATE_REQ           0x0003
#define STUN_ALLOCATE_IND           0x0013
#define STUN_ALLOCATE_SUCCESS_RESP  0x0103
#define STUN_ALLOCATE_ERROR_RESP    0x0113



uint16_t stun_tlv_utils_get_stun_msg_type(stun_msg_t *msg)
{
    uint16_t msg_type = 0;

    switch(msg->hdr.class_type)
    {
        case STUN_REQUEST:
            msg_type = 0x0000 | msg->hdr.method;
            break;

        case STUN_INDICATION:
            msg_type = 0x0010 | msg->hdr.method;
            break;

        case STUN_SUCCESS_RESP:
            msg_type = 0x0100 | msg->hdr.method;
            break;

        case STUN_ERROR_RESP:
            msg_type = 0x0110 | msg->hdr.method;
            break;

        default:
            msg_type = 0;
            break;
    }

    return msg_type;
}


/*============================================================================*/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
