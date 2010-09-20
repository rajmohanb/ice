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



#ifdef ENABLE_TURN
int32_t stun_tlv_utils_get_hmac_key(handle h_msg, u_char *key)
{
    handle h_username, h_realm;
    u_char username[MAX_USERNAME_LEN] = {0}, realm[MAX_REALM_VAL_BYTES] = {0};
    /** TODO - remove magic value 100 for password */
    u_char *ptr, concat_str[MAX_USERNAME_LEN+MAX_REALM_VAL_BYTES+100];
    int32_t status;
    uint32_t num = 1, realm_len, username_len;
    MD5_CTX ctx;

    MD5_Init(&ctx);

    ptr = concat_str;

    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_USERNAME, &h_username, &num);
    if (status != STUN_OK) return status;

    if (num == 0)
    {
        return STUN_INVALID_PARAMS;
    }

    username_len = MAX_USERNAME_LEN;
    status = stun_attr_username_get_user_name(
                                    h_username, username, &username_len);
    if (status != STUN_OK) return status;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_realm, &num);
    if (status != STUN_OK) return status;

    if (num == 0)
    {
        return STUN_INVALID_PARAMS;
    }

    MD5_Update(&ctx, username, username_len);
    MD5_Update(&ctx, ":", 1);

    stun_memcpy(ptr, username, username_len);
    ptr += username_len;

    *ptr = ':';
    ptr++;

    realm_len = MAX_REALM_VAL_BYTES;
    status = stun_attr_realm_get_realm(h_realm, realm, &realm_len);
    if (status != STUN_OK) return status;

    MD5_Update(&ctx, realm, realm_len);
    MD5_Update(&ctx, ":", 1);

    stun_memcpy(ptr, realm, realm_len);
    ptr += realm_len;

    *ptr = ':';
    ptr++;

    MD5_Update(&ctx, "password", strlen("password"));

    stun_memcpy(ptr, "password", strlen("password"));
    ptr += strlen("password");

    //platform_md5((unsigned char*) concat_str, (ptr - concat_str), key);
    MD5_Final(key, &ctx);

    return STUN_OK;
}
#endif



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
