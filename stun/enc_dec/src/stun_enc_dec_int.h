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

#ifndef STUN_ENC_DEC_INT__H
#define STUN_ENC_DEC_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"


#define STUN_MSG_HDR_MSG_LENGTH_OFFSET      2
#define STUN_MSG_HDR_MAGIC_COOKIE_OFFSET    4
#define STUN_MSG_HDR_TXN_ID_OFFSET          8
#define STUN_MSG_HDR_ATTR_OFFSET            20

#define STUN_MSG_CLASS_TYPE_BITMAP          0x0110
#define STUN_MSG_METHOD_TYPE_BITMAP         0x3EEF

#define STUN_XPORT_MAGC_COOKIE_BITMAP       0x2112

#define FINGERPRINT_CRC_XOR_VALUE           0x5354554E

/** comprehension required attribute type range */
#define COMP_REQUIRED_RANGE_MIN             0x0000
#define COMP_REQUIRED_RANGE_MAX             0x7FFF

/** comprehension optional attribute type range */
#define COMP_OPTIONAL_RANGE_MIN             0x8000
#define COMP_OPTIONAL_RANGE_MAX             0xFFFF


typedef int32_t (*stun_attr_tlv_encode) (stun_attr_hdr_t *attr, 
            u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);
typedef int32_t (*stun_attr_tlv_decode) (u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

typedef struct {
    uint32_t              type;
    stun_attr_tlv_encode encode;
    stun_attr_tlv_decode decode;
} stun_attr_tlv_ops_t;


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
