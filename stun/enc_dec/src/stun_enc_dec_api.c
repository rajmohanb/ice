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
#include "stun_enc_dec_int.h"
#include "stun_enc_dec_api.h"
#include "stun_attr_enc_dec.h"
#include "stun_enc_dec_utils.h"


extern stun_attr_tlv_ops_t stun_attr_ops[];


int32_t stun_msg_encode(handle tlv, 
            stun_auth_params_t *auth, u_char *buf, uint32_t *size)
{
    stun_msg_t *msg;
    u_char *packet = buf;
    uint16_t val16, i, len = 0;
    uint32_t val32;
    int32_t status;

    if ((buf == NULL) OR (tlv == NULL) OR (size == NULL))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *) tlv;

    /**
     * check if the message already contains the encoded buffer. This
     * typically happens when a message is being re-transmitted for an 
     * un-reliable transport. If so, then copy the already encoded 
     * buffer and give to the calling application.
     */
    if ((msg->stun_msg != NULL) && (msg->stun_msg_len))
    {
        ICE_LOG (LOG_SEV_INFO, 
                "Earlier encoded message present, hence not encoding "\
                "the message. Returning the cached message of length %d", 
                msg->stun_msg_len);

        if (*size < msg->stun_msg_len)
        {
            ICE_LOG (LOG_SEV_INFO, 
                "Specified buffer length %d not sufficient. The encoded "\
                "buffer length is %d", *size, msg->stun_msg_len);
            return STUN_INVALID_PARAMS;
        }

        *size = msg->stun_msg_len;
        stun_memcpy(buf, msg->stun_msg, msg->stun_msg_len);

        return STUN_OK;
    }

    /** msg class and method */
    val16 = htons(stun_tlv_utils_get_stun_msg_type(msg));
    memcpy(packet, &val16, sizeof(uint16_t));
    len += sizeof(uint16_t);

    /** magic cookie */
    val32 = htonl(msg->hdr.magic_cookie);
    memcpy(packet+STUN_MSG_HDR_MAGIC_COOKIE_OFFSET, &val32, 4);
    len += 4;

    /** transaction id */
    memcpy(packet+STUN_MSG_HDR_TXN_ID_OFFSET, 
                        msg->hdr.trans_id, STUN_TXN_ID_BYTES);
    len += STUN_TXN_ID_BYTES;

    if (msg->attr_count > MAX_STUN_ATTRIBUTES)
        msg->attr_count = MAX_STUN_ATTRIBUTES;

    /** encode attributes */
    for (i = 0; i < msg->attr_count; i++) 
    {
        uint32_t attr_len = 0;

        if (msg->pas_attr[i] == NULL) continue;

        /** encoding of MESSAGE INTEGRITY attribute is a special case */
        if (msg->pas_attr[i]->type == STUN_ATTR_MESSAGE_INTEGRITY)
        {
            status = stun_attr_encode_message_integrity(
                    tlv, msg->pas_attr[i], buf, packet+len+2,
                    *size-len, auth, &attr_len);
        }
        else if (msg->pas_attr[i]->type == STUN_ATTR_FINGERPRINT)
        {
            status = stun_attr_encode_fingerprint(
                    msg->pas_attr[i], buf, packet+len+2, *size-len, &attr_len);
            len += attr_len;
            break;
        }
        else
        {
            status = stun_attr_encode(msg->pas_attr[i], 
                            packet, packet+len+2, *size-len, &attr_len);
        }

        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "Encoding of attribute %d of stun message failed: %d", 
                    msg->pas_attr[i]->type, status);
            status = STUN_ENCODE_FAILED;
            goto ERROR_EXIT;
        }

        len += attr_len;
    }

    /** length field */
    len += sizeof(uint16_t);
    val16 = htons(len - 20);
    memcpy(packet+2, &val16, sizeof(uint16_t));

    /** 
     * store the encoded buffer in the message. This will 
     * avoid re-encoding of the message during re-transmissions.
     */
    msg->stun_msg = (u_char *) stun_calloc (1, len);
    if(msg->stun_msg == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT;
    }
    stun_memcpy(msg->stun_msg, buf, len);
    msg->stun_msg_len = len;

    *size = len;

    return STUN_OK;

ERROR_EXIT:

    return status;
}



int32_t stun_msg_decode(u_char *buf, uint32_t len, handle *tlv)
{
    stun_msg_t *msg;
    u_char *pkt = buf;
    uint16_t val16, attr_len, i;
    uint32_t val32;
    handle h_msg;
    int32_t status;

    if ((buf == NULL) OR (tlv == NULL) OR (len == 0))
        return STUN_INVALID_PARAMS;

    status = stun_msg_create(STUN_REQUEST, STUN_METHOD_BINDING, &h_msg);
    if (status != STUN_OK) return status;

    msg = (stun_msg_t *) h_msg;

    memcpy(&val16, pkt, sizeof(uint16_t));

    switch(ntohs(val16) & STUN_MSG_CLASS_TYPE_BITMAP) {
        case 0x0000: msg->hdr.class_type = STUN_REQUEST; break;
        case 0x0010: msg->hdr.class_type = STUN_INDICATION; break;
        case 0x0100: msg->hdr.class_type = STUN_SUCCESS_RESP; break;
        case 0x0110: msg->hdr.class_type = STUN_ERROR_RESP; break;
        default: 
            msg->hdr.class_type = STUN_MSG_TYPE_MAX;
            status = STUN_INVALID_PARAMS; 
            goto ERROR_EXIT;
    }

    switch(ntohs(val16) & STUN_MSG_METHOD_TYPE_BITMAP) {
        case 0x0001: msg->hdr.method = STUN_METHOD_BINDING; break;
#ifdef ENABLE_TURN
        case 0x0003: msg->hdr.method = STUN_METHOD_ALLOCATE; break;
        case 0x0004: msg->hdr.method = STUN_METHOD_REFRESH; break;
        case 0x0006: msg->hdr.method = STUN_METHOD_SEND; break;
        case 0x0007: msg->hdr.method = STUN_METHOD_DATA; break;
        case 0x0008: msg->hdr.method = STUN_METHOD_CREATE_PERMISSION; break;
        case 0x0009: msg->hdr.method = STUN_METHOD_CHANNEL_BIND; break;
#endif
        default:
            msg->hdr.method = STUN_METHOD_MAX;
            status = STUN_INVALID_PARAMS; 
            goto ERROR_EXIT;
    }

    pkt += 2;

    memcpy(&val16, pkt, sizeof(uint16_t));
    attr_len = ntohs(val16);

    pkt += 2;
    memcpy(&val32, pkt, sizeof(uint32_t));

    if (ntohl(val32) != STUN_MAGIC_COOKIE)
    {
        status = STUN_INVALID_PARAMS;
        goto ERROR_EXIT;
    }

    pkt += 4; 

    memcpy(msg->hdr.trans_id, pkt, STUN_TXN_ID_BYTES);
    pkt += STUN_TXN_ID_BYTES;

    i = 0;

    /** decode attributes */
    while ((pkt < (buf+len)) && (i < MAX_STUN_ATTRIBUTES))
    {
        status = stun_attr_decode(buf, &pkt, (buf+len), &msg->pas_attr[i]);

        if (status != STUN_OK)
        {
            ICE_LOG (LOG_SEV_ERROR, 
                    "Decoding of received stun message failed: %d", status);
            status = STUN_DECODE_FAILED;
            goto ERROR_EXIT;
        }

        msg->attr_count++;
        i++;
    }

    /** make a copy of the received stun message buffer */
    msg->stun_msg = (u_char *) stun_calloc (1, len);
    if (msg->stun_msg == NULL)
    {
        ICE_LOG (LOG_SEV_ERROR, "Memory allocation failed");
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT;
    }

    stun_memcpy(msg->stun_msg, buf, len);
    msg->stun_msg_len = len;

    *tlv = msg;

    return STUN_OK;

ERROR_EXIT:
    stun_msg_destroy(h_msg);

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
