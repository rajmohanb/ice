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

#include <string.h>

#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_utils.h"
#include "stun_enc_dec_int.h"

int32_t stun_msg_layer_create_instance(handle *h_instance)
{
    stun_msg_layer_instance_t *inst;

    if (h_instance == NULL)
        return STUN_INVALID_PARAMS;

    inst = (stun_msg_layer_instance_t *) 
        stun_malloc (sizeof(stun_msg_layer_instance_t));
    if (inst == NULL) return STUN_MEM_ERROR;

    inst->mtu = DEFAULT_MTU;

    *h_instance = inst;

    return STUN_OK;
}


int32_t stun_msg_instance_set_mtu(handle h_instance, uint32_t mtu)
{
    stun_msg_layer_instance_t *inst;

    if (h_instance == NULL)
        return STUN_INVALID_PARAMS;

    inst = (stun_msg_layer_instance_t *)h_instance; 

    inst->mtu = mtu;

    return STUN_OK;
}


int32_t stun_msg_layer_destroy_instance(handle h_instance)
{
    if (h_instance == NULL)
        return STUN_INVALID_PARAMS;

    stun_free(h_instance);

    return STUN_OK;
}


int32_t stun_msg_create(stun_msg_type_t msg_type, 
                            stun_method_type_t method_type, handle *h_msg)
{
    stun_msg_t *msg;

    if (h_msg == NULL)
        return STUN_INVALID_PARAMS;

    if (msg_type >= STUN_MSG_TYPE_MAX)
        return STUN_INVALID_PARAMS;

    if (method_type >= STUN_METHOD_MAX)
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *) stun_calloc (1, sizeof(stun_msg_t));
    if (msg == NULL)
        return STUN_MEM_ERROR;

    msg->hdr.class_type = msg_type;
    msg->hdr.method = method_type;
    msg->hdr.length = 0;
    msg->hdr.magic_cookie = STUN_MAGIC_COOKIE;

    msg->attr_count = 0;

    stun_memset(msg->pas_attr, 0, 
            (sizeof(stun_attr_hdr_t *) * MAX_STUN_ATTRIBUTES));

    msg->stun_msg = NULL;
    msg->stun_msg_len = 0;

    *h_msg = msg;

    return STUN_OK;
}


int32_t stun_msg_destroy(handle h_msg)
{
    stun_msg_t *msg;
    uint32_t i;

    if (h_msg == NULL)
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    for (i = 0; i < MAX_STUN_ATTRIBUTES; i++)
    {
        if (msg->pas_attr[i])
            stun_attr_destroy(msg->pas_attr[i]);
    }

    if (msg->stun_msg) stun_free(msg->stun_msg);

    stun_free(msg);

    return STUN_OK;
}


int32_t stun_msg_get_method(handle h_msg, stun_method_type_t *method)
{
    stun_msg_t *msg;

    if (h_msg == NULL)
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    *method = msg->hdr.method;

    return STUN_OK;
}

int32_t stun_msg_get_class(handle h_msg, stun_msg_type_t *class_type)
{
    stun_msg_t *msg;

    if (h_msg == NULL)
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    *class_type = msg->hdr.class_type;

    return STUN_OK;
}


int32_t stun_msg_get_txn_id(handle h_msg, u_char *txn_id)
{
    stun_msg_t *msg;

    if ((h_msg == NULL) || (txn_id == NULL))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    stun_memcpy(txn_id, msg->hdr.trans_id, STUN_TXN_ID_BYTES);

    return STUN_OK;
}


int32_t stun_msg_set_txn_id(handle h_msg, u_char *txn_id)
{
    stun_msg_t *msg;

    if ((h_msg == NULL) || (txn_id == NULL))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    stun_memcpy(msg->hdr.trans_id, txn_id, STUN_TXN_ID_BYTES);

    return STUN_OK;
}


int32_t stun_msg_get_num_attributes(handle h_msg, uint32_t *num)
{
    stun_msg_t *msg;

    if (h_msg == NULL)
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    *num = msg->attr_count;

    return STUN_OK;
}


int32_t stun_msg_get_specified_attributes(handle h_msg, 
        stun_attribute_type_t attr_type, handle *pah_attr, uint32_t *size)
{
    stun_msg_t *msg;
    stun_attr_hdr_t *attr;
    uint32_t i, count;

    if ((h_msg == NULL) || (pah_attr == NULL) || (*size == 0))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    count = 0;

    for (i = 0; i < msg->attr_count; i++)
    {
        attr = (stun_attr_hdr_t *) msg->pas_attr[i];
        if (!attr) continue;

        if (attr->type == attr_type)
        {
            *pah_attr = attr;
            count++;
            if (count >= *size) break;
            pah_attr++;
        }
    }

    if (count == 0) 
        return STUN_NOT_FOUND;

    *size = count;

    return STUN_OK;
}


int32_t stun_msg_add_attribute(handle h_msg, handle h_attr)
{
    stun_msg_t *msg;
    stun_attr_hdr_t *attr;

    if ((h_msg == NULL) || (h_attr == NULL))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *) h_msg;
    attr = (stun_attr_hdr_t *) h_attr;

    if (attr->type >= STUN_ATTR_MAX)
        return STUN_INVALID_PARAMS;

    if (msg->attr_count == MAX_STUN_ATTRIBUTES)
        return STUN_INT_ERROR;

    msg->pas_attr[msg->attr_count] = h_attr;
    msg->attr_count++;

    return STUN_OK;
}


int32_t stun_msg_remove_attribute(handle h_msg, handle h_attr)
{
    return STUN_OK;
}


int32_t stun_msg_add_attributes(handle h_msg, handle *ah_attr, uint32_t num)
{
    uint32_t i;
    stun_msg_t *msg;
    stun_attr_hdr_t *attr;

    if ((h_msg == NULL) || (ah_attr == NULL) || (num == 0))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *) h_msg;

    for ( i = 0; i < num; i++)
    {
        attr = (stun_attr_hdr_t *) *ah_attr;

        if (attr->type >= STUN_ATTR_MAX)
            return STUN_INVALID_PARAMS;

        if (msg->attr_count == MAX_STUN_ATTRIBUTES)
            goto ERROR_EXIT;

        msg->pas_attr[msg->attr_count] = *ah_attr;
        msg->attr_count++;

        ah_attr++;
    }

    return STUN_OK;

ERROR_EXIT:
    msg->attr_count -= i;
    return STUN_NO_RESOURCE;
}



int32_t stun_msg_create_resp_from_req(handle h_req,
                            stun_msg_type_t msg_type, handle *h_resp)
{
    int32_t status;
    u_char txn_id[STUN_TXN_ID_BYTES];
    stun_method_type_t method;
    handle h_newresp;

    status = stun_msg_get_method(h_req, &method);
    if (status != STUN_OK) return status;

    status = stun_msg_create(msg_type, method, &h_newresp);
    if (status != STUN_OK) return status;

    /** copy the transaction id */
    status = stun_msg_get_txn_id(h_req, txn_id);
    if (status != STUN_OK) goto ERROR_EXIT;

    status = stun_msg_set_txn_id(h_newresp, txn_id);
    if (status != STUN_OK) goto ERROR_EXIT;

    *h_resp = h_newresp; 
    return STUN_OK;

ERROR_EXIT:
    stun_msg_destroy(h_newresp);
    
    return status;
}


int32_t stun_msg_validate_message_integrity(
                            handle h_msg, u_char *key, uint32_t key_len)
{
    handle h_msg_intg;
    uint32_t num;
    int32_t status;
    stun_msg_integrity_attr_t *msg_intg;
    stun_msg_t *msg;
    u_char *buf, hmac[20];
    uint16_t val16;

    if ((h_msg == NULL) || (key == NULL) || (key_len == 0))
        return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_MESSAGE_INTEGRITY, &h_msg_intg, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Extracting message integrity attribute from message "\
            "returned error: %d", status);
        return STUN_VALIDATON_FAIL;
    }

    if (num == 0)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "MESSAGE-INTEGRITY attribute missing in the message");
        return STUN_VALIDATON_FAIL;
    }

    msg_intg = (stun_msg_integrity_attr_t *) h_msg_intg;
    buf = msg->stun_msg;

    /** 
     * prepare the raw stun buffer for validation. The length of the stun
     * message header should be set to include the length of the message
     * integrity attribute itself. '20' is stun message header and '24'
     * is the message integrity attribute length.
     */
    val16 = msg_intg->position + 24 - 20;
    val16 = htons(val16);
    stun_memcpy(buf+2, &val16, sizeof(uint16_t));

    /** compute the hmac digest */
    platform_hmac_sha((char *)key, key_len, 
            (char *)buf, msg_intg->position, (char *)hmac, 20);

    /** 
     * now that the hmac is computed, restore the length value 
     * in the stun message header to the actual value.
     */
    val16 = htons(msg->hdr.length);
    stun_memcpy(buf+2, &val16, sizeof(uint16_t));

    /** validate the computed hmac against the one received in the message */
    if (stun_memcmp(msg_intg->hmac, hmac, STUN_ATTR_MSG_INTEGRITY_LEN) != 0)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "MESSAGE-INTEGRITY value mismatch. Validation failed");
        return STUN_VALIDATON_FAIL;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "MESSAGE-INTEGRITY value matched. Validation succeeded");
    return STUN_OK;
}


int32_t stun_msg_validate_fingerprint(handle h_msg)
{
    handle h_fingerprint;
    uint32_t num, crc32 = 0;
    int32_t status;
    stun_fingerprint_attr_t *fingerprint;
    stun_msg_t *msg;
    u_char *msg_start;
    uint16_t val16;

    if (h_msg == NULL) return STUN_INVALID_PARAMS;

    msg = (stun_msg_t *)h_msg;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_FINGERPRINT, &h_fingerprint, &num);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
            "Extracting fingerprint attribute from message "\
            "returned error: %d", status);
        return STUN_VALIDATON_FAIL;
    }

    if (num == 0)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "FINGERPRINT attribute missing in the message");
        return STUN_VALIDATON_FAIL;
    }

    fingerprint = (stun_fingerprint_attr_t *) h_fingerprint;
    msg_start = msg->stun_msg;

    /** 
     * prepare the raw stun buffer for validation. The CRC used in the
     * FINGERPRINT attribute covers the length field from the STUN
     * message header. Therefore, this value must be correct and include
     * the CRC attribute as part of the message length, prior to
     * computation of the CRC. '20' is stun message header and '8' is
     * fingerprint attribute length.
     */
    val16 = fingerprint->position + 8 - 20;
    val16 = htons(val16);
    stun_memcpy(msg_start+2, &val16, sizeof(uint16_t));

    /** compute the CRC value */
    crc32 = platform_crc32(msg_start, fingerprint->position);

    /** 
     * in order to compare, this computed value needs to be 
     * XOR'ed and then converted to network byte order.
     */
    crc32 ^= FINGERPRINT_CRC_XOR_VALUE;
    ICE_LOG (LOG_SEV_INFO, "Calculated CRC after XOR %x\n", crc32);

    /** 
     * now that the CRC is computed, restore the length value 
     * in the stun message header to the actual value.
     */
    val16 = htons(msg->hdr.length);
    stun_memcpy(msg_start+2, &val16, sizeof(uint16_t));

    /** validate the computed hmac against the one received in the message */
    if (fingerprint->value != crc32)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "FINGERPRINT value mismatch. Validation failed");
        return STUN_VALIDATON_FAIL;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "FINGERPRINT value matched. Validation succeeded");
    return STUN_OK;
}



int32_t stun_msg_verify_if_valid_stun_packet(u_char *pkt, uint32_t pkt_len)
{
    uint16_t attr_len;

    /** all stun messages MUST start with a 20-byte header */
    if (pkt_len < STUN_MSG_HEADER_SIZE) return STUN_MSG_NOT;

    /** most significant 2 bits of every STUN message MUST be zeroes */
    if ((*pkt & 0xC0) > 0) return STUN_MSG_NOT;

    /** 
     * the magic cookie field MUST contain the 
     * fixed value 0x2112A442 in network byte order.
     */
    if ((*(pkt+4) != 0x21) || (*(pkt+5) != 0x12) || 
            (*(pkt+6) != 0xA4) || (*(pkt+7) != 0x42))
        return STUN_MSG_NOT;

    /**
     * since all STUN attributes are padded to a multiple of 4 bytes, 
     * the last 2 bits if the message length field are always zero.
     */
    stun_memcpy(&attr_len, pkt+2, sizeof(uint16_t));
    attr_len = ntohs(attr_len);

    if ((attr_len & 0x03) != 0) return STUN_MSG_NOT;

    if ((attr_len + STUN_MSG_HEADER_SIZE) != pkt_len) return STUN_MSG_NOT;

    /** verify fingerprint */

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
