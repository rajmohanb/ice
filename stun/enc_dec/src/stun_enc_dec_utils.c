/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2011, MindBricks Technologies               *
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


static s_char *gs_stun_msg_types[] =
{
    "REQUEST",
    "INDICATION",
    "SUCCESS_RESP",
    "ERROR_RESP"
};


static s_char *gs_stun_method_types[] =
{
    "",
    "STUN BINDING",
#ifdef MB_ENABLE_TURN
    "STUN ALLOCATE",
    "STUN REFRESH",
    "STUN SEND",
    "STUN DATA",
    "STUN CREATE_PERMISSION",
    "STUN CHANNEL_BIND",
#endif
    "",
};


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



uint32_t stun_enc_dec_utils_print_binary_buffer(
        u_char *dest, uint32_t dest_len, u_char *src, uint32_t src_len)
{
    uint32_t i, bytes = 0;

    bytes += stun_snprintf((char *)dest, dest_len, "0x");

    for (i = 0; ((i < src_len) && (bytes <= dest_len)); i++)
        bytes += stun_snprintf((char *)dest+bytes, 
                            (dest_len - bytes), "%2.2X", *(src+i));

    return bytes;
}



int32_t stun_enc_dec_utils_print_msg_header(
                        stun_msg_t *msg, u_char *buf, uint32_t *buf_len)
{
    uint32_t i, bytes = 0;

    bytes += stun_snprintf((char *)buf, 
                    (*buf_len - bytes), "STUN Message:\nHeader:\n");

    bytes += stun_snprintf((char *)buf+bytes, (*buf_len - bytes), 
            "   Msg Type: [%s %s]\n", gs_stun_method_types[msg->hdr.method],
            gs_stun_msg_types[msg->hdr.class_type]);

    if (msg->stun_msg_len)
    {
        bytes += stun_snprintf((char *)buf+bytes, (*buf_len - bytes), 
                                    "   Length: %d\n", msg->stun_msg_len);
    }
    else
    {
        bytes += stun_snprintf((char *)buf+bytes, 
                (*buf_len - bytes), "   Length: computed while sending msg\n");
    }

    bytes += stun_snprintf((char *)buf+bytes, (*buf_len - bytes), 
            "   Cookie: 0x%8.8X\n", msg->hdr.magic_cookie);

    bytes += stun_snprintf((char *)buf+bytes, 
            (*buf_len - bytes), "   Txn ID: 0x");
    for (i = 0; i < STUN_TXN_ID_BYTES; i++)
        bytes += stun_snprintf((char *)buf+bytes, 
                (*buf_len - bytes), "%2.2X", msg->hdr.trans_id[i]);

    bytes += stun_snprintf((char *)buf+bytes, (*buf_len - bytes), "\n");

    *buf_len = bytes;

    return STUN_OK;
}



/*============================================================================*/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
