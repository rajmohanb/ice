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



#ifdef MB_ENABLE_TURN

int32_t stun_enc_dec_utils_get_long_term_cred_hmac_key(handle h_msg, 
                                stun_auth_params_t *auth_params, u_char *key)
{
    handle h_username, h_realm;
    u_char *username, *realm;
    int32_t status;
    uint32_t num, realm_len, username_len;
    stun_MD5_CTX ctx;

    stun_MD5_Init(&ctx);

    /** username */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_USERNAME, &h_username, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "USERNAME attribute missing in the message?");
        return status;
    }

    status = stun_attr_username_get_username_length(
                                    h_username, &username_len);
    if (status != STUN_OK) return status;

    username = (u_char *) stun_calloc (1, username_len);
    if (username == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Memory allocation for username failed %d bytes.", username_len);

        return STUN_MEM_ERROR;
    }

    status = stun_attr_username_get_username(
                                    h_username, username, &username_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Retrieving username from attribute failed %d", status);
        goto ERROR_EXIT_PT_1;
    }

    stun_MD5_Update(&ctx, username, username_len);
    stun_MD5_Update(&ctx, ":", 1);


    /** realm */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_realm, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "REALM attribute missing in the message?");
        goto ERROR_EXIT_PT_1;
    }

    status = stun_attr_realm_get_realm_length(h_realm, &realm_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT_1;

    realm = (u_char *) stun_calloc (1, realm_len);
    if (realm == NULL)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Memory allocation for realm failed %d bytes.", realm_len);
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT_PT_1;
    }

    status = stun_attr_realm_get_realm(h_realm, realm, &realm_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Retrieving realm from attribute failed %d", status);
        goto ERROR_EXIT_PT_2;
    }

    stun_MD5_Update(&ctx, realm, realm_len);
    stun_MD5_Update(&ctx, ":", 1);

    stun_MD5_Update(&ctx, auth_params->password, auth_params->len);

    stun_MD5_Final(key, &ctx);

    stun_free(username);
    stun_free(realm);

    return STUN_OK;

ERROR_EXIT_PT_2:
    stun_free(realm);
ERROR_EXIT_PT_1:
    stun_free(username);

    return status;
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
