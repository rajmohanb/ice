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

#include "types.h"
#include <netinet/in.h>
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_enc_dec_api.h"
#include "stun_enc_dec_int.h"
#include "stun_attr_enc_dec.h"
#include "stun_enc_dec_utils.h"

static stun_attr_tlv_ops_t stun_attr_ops[] = {
    {
        STUN_ATTR_MAPPED_ADDR,
        stun_attr_encode_mapped_address,
        stun_attr_decode_mapped_address,
    },
    {
        STUN_ATTR_USERNAME,
        stun_attr_encode_username,
        stun_attr_decode_username,
    },
    {
        STUN_ATTR_MESSAGE_INTEGRITY,
        NULL, /** place holder, defined elsewhere */
        stun_attr_decode_message_integrity,
    },
    {
        STUN_ATTR_ERROR_CODE,
        stun_attr_encode_error_code,
        stun_attr_decode_error_code,
    },
    {
        STUN_ATTR_UNKNOWN_ATTRIBUTES,
        stun_attr_encode_unknown_attributes,
        stun_attr_decode_unknown_attributes,
    },
    {
        STUN_ATTR_REALM,
        stun_attr_encode_realm,
        stun_attr_decode_realm,
    },
    {
        STUN_ATTR_NONCE,
        stun_attr_encode_nonce,
        stun_attr_decode_nonce,
    },
    {
        STUN_ATTR_XOR_MAPPED_ADDR,
        stun_attr_encode_xor_mapped_address,
        stun_attr_decode_xor_mapped_address
    },
    {
        STUN_ATTR_SOFTWARE,
        stun_attr_encode_software,
        stun_attr_decode_software,
    },
    {
        STUN_ATTR_ALTERNATE_SERVER,
        stun_attr_encode_alternate_server,
        stun_attr_decode_alternate_server,
    },
    {
        STUN_ATTR_FINGERPRINT,
        NULL,
        stun_attr_decode_fingerprint,
    },
#ifdef ENABLE_TURN
    {
        STUN_ATTR_CHANNEL_NUMBER,
        stun_attr_encode_channel_number,
        stun_attr_decode_channel_number,
    },
    {
        STUN_ATTR_LIFETIME,
        stun_attr_encode_lifetime,
        stun_attr_decode_lifetime,
    },
    {
        STUN_ATTR_XOR_PEER_ADDR,
        stun_attr_encode_xor_peer_address,
        stun_attr_decode_xor_peer_address,
    },
    {
        STUN_ATTR_DATA,
        stun_attr_encode_data,
        stun_attr_decode_data,
    },
    {
        STUN_ATTR_XOR_RELAYED_ADDR,
        stun_attr_encode_xor_relayed_address,
        stun_attr_decode_xor_relayed_address,
    },
    {
        STUN_ATTR_EVEN_PORT,
        stun_attr_encode_even_port,
        stun_attr_decode_even_port,
    },
    {
        STUN_ATTR_REQUESTED_TRANSPORT,
        stun_attr_encode_requested_transport,
        stun_attr_decode_requested_transport,
    },
    {
        STUN_ATTR_DONT_FRAGMENT,
        stun_attr_encode_dont_fragment,
        stun_attr_decode_dont_fragment,
    },
    {
        STUN_ATTR_RESERVATION_TOKEN,
        stun_attr_encode_reservation_token,
        stun_attr_decode_reservation_token,
    },
#endif
#ifdef ENABLE_ICE
    {
        STUN_ATTR_PRIORITY,
        stun_attr_encode_priority,
        stun_attr_decode_priority,
    },
    {
        STUN_ATTR_USE_CANDIDATE,
        stun_attr_encode_use_candidate,
        stun_attr_decode_use_candidate,
    },
    {
        STUN_ATTR_ICE_CONTROLLED,
        stun_attr_encode_ice_controlled,
        stun_attr_decode_ice_controlled,
    },
    {
        STUN_ATTR_ICE_CONTROLLING,
        stun_attr_encode_ice_controlling,
        stun_attr_decode_ice_controlling,
    },
#endif
};


/*============================================================================*/

int32_t stun_attr_encode(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len)
{

    uint32_t i;
    static uint16_t max_attr_elems = 
        sizeof(stun_attr_ops)/sizeof(stun_attr_tlv_ops_t);

    for(i = 0; i < max_attr_elems; i++) {

        if(attr->type == stun_attr_ops[i].type) {
            return stun_attr_ops[i].encode(attr, buf_head, buf, max_len, len);
        }
    }

    return STUN_INVALID_PARAMS;
}


int32_t stun_attr_decode(u_char *buf_head, 
            u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr)
{
    uint16_t val16, i;
    u_char *pkt = *buf;
    int32_t status;
    static uint16_t max_attr_elems = 
        sizeof(stun_attr_ops)/sizeof(stun_attr_tlv_ops_t);

    memcpy(&val16, pkt, sizeof(uint16_t));
    val16 = ntohs(val16);

    pkt += 2;

    for(i = 0; i < max_attr_elems; i++) {

        if(val16 == stun_attr_ops[i].type) {
            status = stun_attr_ops[i].decode(buf_head, &pkt, buf_end, attr);
            *buf = pkt;
            return status;
        }
    }

    /** decode as unknown attribute */
    status = stun_attr_decode_extended_attr(val16, 
                                        buf_head, &pkt, buf_end, attr);
    *buf = pkt;
    return status;
}

/*============================================================================*/


int32_t stun_attr_encode_mapped_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_mapped_addr_attr_t *addr;
    uint16_t val16;
    u_char *hdr_len;

    addr = (stun_mapped_addr_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_MAPPED_ADDR);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    hdr_len = buf;
    buf += sizeof(uint16_t);

    /** empty byte */
    buf++;

    /** family */
    *buf = addr->family;
    buf++;

    /** port */
    val16 = htons(addr->port);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** address */
    if(addr->family == STUN_ADDR_FAMILY_IPV4) {
        struct in_addr mapped_addr;

        if (inet_aton((char *)addr->address, &mapped_addr) == 0)
        {
            return STUN_INVALID_PARAMS;
        }

        memcpy(buf, &mapped_addr, sizeof(uint32_t));
        buf += sizeof(uint32_t);
    } else {
        struct in6_addr mapped_addr;

        if (inet_pton(AF_INET6, (char *)addr->address, &mapped_addr) <= 0)
        {
            return STUN_INVALID_PARAMS;
        }

        memcpy(buf, &mapped_addr, 16);
        buf += 16;
    }

    /** length */
    val16 = htons(buf - hdr_len - 2);
    memcpy(hdr_len, &val16, sizeof(uint16_t));

    /** no padding required */

    *len = buf - hdr_len + 2;

    return STUN_OK;
}


int32_t stun_attr_decode_mapped_address(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_mapped_addr_attr_t *addr;
    uint16_t val16;
    u_char *pkt = *buf;
    int32_t status = STUN_OK;

    addr = (stun_mapped_addr_attr_t *) 
                        stun_calloc (1, sizeof(stun_mapped_addr_attr_t));
    if (addr == NULL) return STUN_MEM_ERROR;

    addr->hdr.type = STUN_ATTR_MAPPED_ADDR;

    memcpy(&val16, pkt, sizeof(uint16_t));
    addr->hdr.length = ntohs(val16);

    pkt += 2;

    /** skip on byte */
    pkt += 1;

    /** family */
    addr->family = *pkt;
    pkt += 1;

    /** port */
    memcpy(&val16, pkt, sizeof(uint16_t));
    addr->port = ntohs(val16);
    pkt += 2;

    if(addr->family == STUN_ADDR_FAMILY_IPV4) {
        struct in_addr mapped_addr;
        memcpy(&mapped_addr.s_addr, pkt, 4);
        pkt += 4;
        strncpy((char *)addr->address, 
                inet_ntoa(mapped_addr), MAX_MAPPED_ADDRESS_LEN - 1);
    } else {

        if (inet_ntop(AF_INET6, pkt, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
        {
            perror("inet_ntop: ");
            ICE_LOG(LOG_SEV_ERROR, "inet_ntop() returned NULL");
            status = STUN_DECODE_FAILED;
        }
        pkt += 16;
    }

    *attr = (stun_attr_hdr_t *) addr;

    *buf = pkt;

    return status;
}

/*============================================================================*/

int32_t stun_attr_encode_username(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_username_attr_t *username;
    uint16_t val16, pad_bytes = 0;

    username = (stun_username_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_USERNAME);
    memcpy(buf, &val16, sizeof(uint16_t));

    buf += sizeof(uint16_t);

    /** username value */
    stun_memcpy(buf+2, username->username, username->hdr.length);

    /** length */
    val16 = htons(username->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));

    /** padding */
    if (username->hdr.length % 4)
    {
        pad_bytes = 4 - (username->hdr.length % 4);
    }
    buf += pad_bytes;

    *len = username->hdr.length + pad_bytes + 4;
    
    return STUN_OK;
}


int32_t stun_attr_decode_username(u_char *buf_head, u_char **buf, 
                            u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_username_attr_t *username;
    uint16_t val16;
    u_char *pkt = *buf;

    username = (stun_username_attr_t *) 
                        stun_calloc (1, sizeof(stun_username_attr_t));
    if (username == NULL) return STUN_MEM_ERROR;

    username->hdr.type = STUN_ATTR_USERNAME;

    memcpy(&val16, pkt, sizeof(uint16_t));
    username->hdr.length = ntohs(val16);
    pkt += 2;

    username->username = stun_calloc(1, username->hdr.length);
    if(username->username == NULL) return STUN_MEM_ERROR;

    memcpy(username->username, pkt, username->hdr.length);
    pkt +=  username->hdr.length;

    if (username->hdr.length % 4)
    {
        pkt += 4 - (username->hdr.length % 4);
    }

    *attr = (stun_attr_hdr_t *)username;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_message_integrity(handle h_msg, 
        stun_attr_hdr_t *attr, u_char *msg_start, u_char *buf, 
        uint32_t max_len, stun_auth_params_t *auth, uint32_t *len) {

    stun_msg_integrity_attr_t *integrity;
    stun_method_type_t method;
    uint16_t val16, key_len;
    u_char md5_key[16], hmac[20];

    integrity = (stun_msg_integrity_attr_t *) attr;
    integrity->hdr.length = MSG_INTEGRITY_HMAC_BYTES;

    /** attribute type */
    val16 = htons(STUN_ATTR_MESSAGE_INTEGRITY);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** length */
    val16 = htons(integrity->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    stun_msg_get_method(h_msg, &method);

    /** hmac */
    stun_memset(buf, 0, MSG_INTEGRITY_HMAC_BYTES);
    buf += MSG_INTEGRITY_HMAC_BYTES;

#ifdef ENABLE_TURN
    if (method == STUN_METHOD_ALLOCATE)
    {
        /** compute the hmac key - long term credentials */
        stun_tlv_utils_get_hmac_key(h_msg, md5_key);
        key_len = 16;
    }
    else
#endif
    {
        /** short term credential */
        strncpy((char *)md5_key, (char *)auth->password, auth->len);
        key_len = auth->len;
    }

    /** before computing the hmac digest, set the length of the msg */
    val16 = (uint16_t) (buf - msg_start - 20);
    val16 = htons(val16);
    stun_memcpy(msg_start+2, &val16, sizeof(uint16_t));

    /** compute the hmac digest */
    platform_hmac_sha((char *)md5_key, key_len, 
            (char *)msg_start, (buf-msg_start - 24), (char *)hmac, 20);

    stun_memcpy((buf-MSG_INTEGRITY_HMAC_BYTES), hmac, 20);

    *len = integrity->hdr.length + 4;
    return STUN_OK;
}


int32_t stun_attr_decode_message_integrity(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_msg_integrity_attr_t *msg_integrity;
    uint16_t val16;
    u_char *pkt = *buf;

    msg_integrity = (stun_msg_integrity_attr_t *) 
                        stun_calloc (1, sizeof(stun_msg_integrity_attr_t));
    if (msg_integrity == NULL) return STUN_MEM_ERROR;

    msg_integrity->hdr.type = STUN_ATTR_MESSAGE_INTEGRITY;

    /** 
     * store the position at which the message integrity attribute appeared 
     * in the received stun message. The value '2' is deducted because 'pkt'
     * already points to value part of the message integrity attribute header.
     * The called function has already moved the 'pkt' to point beyond the 
     * attribute type.
     */
    msg_integrity->position = pkt - buf_head - 2;

    memcpy(&val16, pkt, sizeof(uint16_t));
    msg_integrity->hdr.length = ntohs(val16);

    pkt += 2;

    if (msg_integrity->hdr.length != MSG_INTEGRITY_HMAC_BYTES)
    {
        stun_free(msg_integrity);
        return STUN_DECODE_FAILED;
    }

    memcpy(msg_integrity->hmac, pkt, MSG_INTEGRITY_HMAC_BYTES);
    pkt += MSG_INTEGRITY_HMAC_BYTES;

    *attr = (stun_attr_hdr_t *)msg_integrity;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_error_code(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_error_code_attr_t *error_code;
    uint16_t val16, pad_bytes = 0;

    error_code = (stun_error_code_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_ERROR_CODE);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** length */
    val16 = htons(error_code->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** error code - first 2 bytes are reserved */
    *buf = 0; buf++;
    *buf = 0; buf++;
    *buf = (error_code->code/100); buf++;
    *buf = (error_code->code%100); buf++;

    /** error reason */
    stun_memcpy(buf, error_code->reason, (error_code->hdr.length - 4));
    buf += error_code->hdr.length - 4;

    /** padding */
    if (error_code->hdr.length % 4)
    {
        pad_bytes = 4 - (error_code->hdr.length % 4);
    }
    buf += pad_bytes;

    *len = error_code->hdr.length + pad_bytes + 4;
    
    return STUN_OK;
}


int32_t stun_attr_decode_error_code(u_char* buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_error_code_attr_t *error_code;
    uint16_t val16;
    int32_t status;
    u_char *pkt = *buf;

    error_code = (stun_error_code_attr_t *) 
                        stun_calloc (1, sizeof(stun_error_code_attr_t));
    if (error_code == NULL) return STUN_MEM_ERROR;

    error_code->hdr.type = STUN_ATTR_ERROR_CODE;

    memcpy(&val16, pkt, sizeof(uint16_t));
    error_code->hdr.length = ntohs(val16);

    pkt += 2;

    /** skip 2 reserved bytes out of 21 bits */
    pkt += 2;

    /** error code class */
    error_code->code = *pkt;
    error_code->code = error_code->code & 0x07;
    error_code->code *= 100;
    pkt += 1;

    /** error code number */
    error_code->code += *pkt;
    pkt += 1;

    error_code->reason = stun_calloc(1, error_code->hdr.length - 4);
    if (error_code->reason == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT;
    }

    memcpy(error_code->reason, pkt, error_code->hdr.length - 4);
    pkt += (error_code->hdr.length - 4);

    if (error_code->hdr.length % 4)
    {
        pkt += 4 - (error_code->hdr.length % 4);
    }

    *attr = (stun_attr_hdr_t *) error_code;

    *buf = pkt;

    return STUN_OK;

ERROR_EXIT:

    stun_free(error_code);
    return status;
}

/*============================================================================*/

int32_t stun_attr_encode_unknown_attributes(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_unknown_attributes_attr_t *unknown_attrs;
    uint16_t val16, i, pad_bytes = 0;
    u_char *temp = buf;

    unknown_attrs = (stun_unknown_attributes_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_UNKNOWN_ATTRIBUTES);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** length */
    val16 = htons(unknown_attrs->count * sizeof(uint16_t));
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** add attribute types */
    for (i = 0; i < unknown_attrs->count; i++)
    {
        val16 = htons(unknown_attrs->attr_types[i]);
        stun_memcpy(buf, &val16, sizeof(uint16_t));
        buf += sizeof(uint16_t);
    }

    /** padding */
    if (unknown_attrs->count % 2)
    {
        buf += pad_bytes;
    }

    *len = buf - temp;
    
    return STUN_OK;
}


int32_t stun_attr_decode_unknown_attributes(u_char *buf_head, u_char **buf, 
                        u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_realm(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_realm_attr_t *realm;
    uint16_t val16, pad_bytes = 0;

    realm = (stun_realm_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_REALM);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** nonce value */
    stun_memcpy(buf+2, realm->realm, realm->hdr.length);

    /** length */
    val16 = htons(realm->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));

    /** padding */
    if (realm->hdr.length % 4)
    {
        pad_bytes = 4 - (realm->hdr.length % 4);
    }
    buf += pad_bytes;

    *len = realm->hdr.length + pad_bytes + 4;
    
    return STUN_OK;
}


int32_t stun_attr_decode_realm(u_char *buf_head, u_char **buf, 
                            u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_realm_attr_t *realm;
    uint16_t val16;
    int32_t status;
    u_char *pkt = *buf;

    realm = (stun_realm_attr_t *) 
                        stun_calloc (1, sizeof(stun_realm_attr_t));
    if (realm == NULL) return STUN_MEM_ERROR;

    realm->hdr.type = STUN_ATTR_REALM;

    memcpy(&val16, pkt, sizeof(uint16_t));
    realm->hdr.length = ntohs(val16);
    pkt += 2;

    realm->realm = stun_calloc(1, realm->hdr.length);
    if (realm->realm == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT;
    }

    memcpy(realm->realm, pkt, realm->hdr.length);
    pkt +=  realm->hdr.length;

    if (realm->hdr.length % 4)
    {
        pkt += 4 - (realm->hdr.length % 4);
    }

    *attr = (stun_attr_hdr_t *)realm;
    *buf = pkt;

    return STUN_OK;

ERROR_EXIT:

    stun_free(realm);
    return status;
}

/*============================================================================*/

int32_t stun_attr_encode_nonce(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_nonce_attr_t *nonce;
    uint16_t val16, pad_bytes = 0;

    nonce = (stun_nonce_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_NONCE);
    memcpy(buf, &val16, sizeof(uint16_t));

    buf += sizeof(uint16_t);

    /** nonce value */
    stun_memcpy(buf+2, nonce->nonce, nonce->hdr.length);

    /** length */
    val16 = htons(nonce->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));

    /** padding */
    if (nonce->hdr.length % 4)
    {
        pad_bytes = 4 - (nonce->hdr.length % 4);
    }
    buf += pad_bytes;

    *len = nonce->hdr.length + pad_bytes + 4;
    
    return STUN_OK;
}


int32_t stun_attr_decode_nonce(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_nonce_attr_t *nonce;
    uint16_t val16;
    int32_t status;
    u_char *pkt = *buf;

    nonce = (stun_nonce_attr_t *) 
                        stun_calloc (1, sizeof(stun_nonce_attr_t));
    if (nonce == NULL) return STUN_MEM_ERROR;

    nonce->hdr.type = STUN_ATTR_NONCE;

    memcpy(&val16, pkt, sizeof(uint16_t));
    nonce->hdr.length = ntohs(val16);
    pkt += 2;

    nonce->nonce = stun_calloc(1, nonce->hdr.length);
    if (nonce->nonce == NULL)
    {
        status = STUN_MEM_ERROR;
        goto ERROR_EXIT;
    }

    memcpy(nonce->nonce, pkt, nonce->hdr.length);
    pkt +=  nonce->hdr.length;

    if (nonce->hdr.length % 4)
    {
        pkt += 4 - (nonce->hdr.length % 4);
    }

    *attr = (stun_attr_hdr_t *)nonce;
    *buf = pkt;

    return STUN_OK;

ERROR_EXIT:

    stun_free(nonce);
    return status;
}

/*============================================================================*/

int32_t stun_attr_encode_xor_mapped_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_xor_mapped_addr_attr_t *addr;
    uint16_t val16;
    u_char *hdr_len;

    addr = (stun_xor_mapped_addr_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_XOR_MAPPED_ADDR);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    hdr_len = buf;
    buf += sizeof(uint16_t);

    /** empty byte */
    buf++;

    /** family */
    *buf = addr->family;
    buf++;

    /** port */
    val16 = addr->port ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    val16 = htons(val16);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** address */
    if(addr->family == STUN_ADDR_FAMILY_IPV4) {
        struct in_addr mapped_addr;
        uint32_t val32;

        if (inet_aton((char *)addr->address, &mapped_addr) == 0)
        {
            return STUN_INVALID_PARAMS;
        }
        mapped_addr.s_addr = ntohl(mapped_addr.s_addr);
        mapped_addr.s_addr ^= STUN_MAGIC_COOKIE;
        val32 = htonl(mapped_addr.s_addr);

        memcpy(buf, &val32, sizeof(uint32_t));
        buf += sizeof(uint32_t);
    } else {

        u_char xor_addr[16];
        uint32_t i;

        if (inet_pton(AF_INET6, (char *)addr->address, xor_addr) <= 0)
        {
            return STUN_INVALID_PARAMS;
        }

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        memcpy(buf, xor_addr, 16);
        buf += 16;
    }

    /** length */
    val16 = htons(buf - hdr_len - 2);
    memcpy(hdr_len, &val16, sizeof(uint16_t));

    /** no padding required */

    *len = buf - hdr_len + 2;

    return STUN_OK;
}


int32_t stun_attr_decode_xor_mapped_address(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_xor_mapped_addr_attr_t *addr;
    uint16_t val16, i;
    u_char *pkt = *buf;

    addr = (stun_xor_mapped_addr_attr_t *) 
                stun_calloc (1, sizeof(stun_xor_mapped_addr_attr_t));
    if (addr == NULL) return STUN_MEM_ERROR;

    addr->hdr.type = STUN_ATTR_XOR_MAPPED_ADDR;

    memcpy(&val16, pkt, sizeof(uint16_t));
    addr->hdr.length = ntohs(val16);
    pkt += 2;

    /** skip one byte */
    pkt += 1;

    /** family */
    addr->family = *pkt;
    pkt += 1;

    /** port */
    memcpy(&val16, pkt, sizeof(uint16_t));
    val16 = ntohs(val16);
    addr->port = val16 ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    pkt += 2;

    if(addr->family == STUN_ADDR_FAMILY_IPV4) {

#if 1
        u_char xor_addr[4];
        memcpy(xor_addr, pkt, 4);

        for (i =0 ; i < 4; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
        {
            perror("inet_ntop: ");
        }
        pkt += 4;
#else
        struct in_addr mapped_addr;
        uint32_t val32;
        memcpy(&val32, pkt, 4);
        mapped_addr.s_addr = ntohl(val32);
        mapped_addr.s_addr ^= STUN_MAGIC_COOKIE;
        mapped_addr.s_addr = htonl(mapped_addr.s_addr);
        pkt += 4;
        strncpy((char *)addr->address, 
                inet_ntoa(mapped_addr), MAX_MAPPED_ADDRESS_LEN - 1);
#endif

    } else {

        u_char xor_addr[16];

        memcpy(xor_addr, pkt, 16);

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET6, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
            perror("inet_ntop: ");
        pkt += 16;
    }

    *attr = (stun_attr_hdr_t *) addr;

    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_software(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_software_attr_t *software;
    uint16_t val16, pad_bytes = 0;

    software = (stun_software_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_SOFTWARE);
    memcpy(buf, &val16, sizeof(uint16_t));

    buf += sizeof(uint16_t);

    /** software value */
    stun_memcpy(buf + 2, software->software, software->hdr.length);

    val16 = htons(software->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));

    /** padding */
    if (software->hdr.length % 4)
    {
        pad_bytes = 4 - (software->hdr.length % 4);
    }
    buf += pad_bytes;

    *len = software->hdr.length + pad_bytes + 4;

    return STUN_OK;
}

int32_t stun_attr_decode_software(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_software_attr_t *software;
    uint16_t val16;
    u_char *pkt = *buf;

    software = (stun_software_attr_t *) 
                        stun_calloc (1, sizeof(stun_software_attr_t));
    if (software == NULL) return STUN_MEM_ERROR;

    software->hdr.type = STUN_ATTR_SOFTWARE;

    memcpy(&val16, pkt, sizeof(uint16_t));
    software->hdr.length = ntohs(val16);
    pkt += 2;

    software->software = stun_calloc(1, software->hdr.length);
    if(software->software == NULL) return STUN_MEM_ERROR;

    memcpy(software->software, pkt, software->hdr.length);
    pkt +=  software->hdr.length;

    if (software->hdr.length % 4)
    {
        pkt += (4 -  (software->hdr.length % 4));
    }

    *attr = (stun_attr_hdr_t *)software;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_alternate_server(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_alternate_server(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_fingerprint(stun_attr_hdr_t *attr, 
            u_char *msg_start, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_fingerprint_attr_t *fingerprint;
    uint16_t val16;
    uint32_t crc32;

    fingerprint = (stun_fingerprint_attr_t *) attr;
    fingerprint->hdr.length = STUN_ATTR_FINGERPRINT_SIZE;

    /** attribute type */
    val16 = htons(STUN_ATTR_FINGERPRINT);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    val16 = htons(fingerprint->hdr.length);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    stun_memset(buf, 0, STUN_ATTR_FINGERPRINT_SIZE);
    buf += STUN_ATTR_FINGERPRINT_SIZE;

    /** setup the header length for fingerprint */
    val16 = (uint16_t) (buf - msg_start - 20);
    val16 = htons(val16);
    stun_memcpy(msg_start+2, &val16, sizeof(uint16_t));

    /** calculate crc32 */
    crc32 = platform_crc32(msg_start, (buf - msg_start - 8));

    crc32 ^= FINGERPRINT_CRC_XOR_VALUE;
    ICE_LOG (LOG_SEV_INFO, "Calculated CRC after XOR %x\n", crc32);

    crc32 = htonl(crc32);
    stun_memcpy((buf-STUN_ATTR_FINGERPRINT_SIZE), &crc32, sizeof(uint32_t));

    *len = fingerprint->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_fingerprint(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_fingerprint_attr_t *fingerprint;
    uint16_t val16;
    uint32_t val32;
    u_char *pkt = *buf;

    fingerprint = (stun_fingerprint_attr_t *) 
                        stun_calloc (1, sizeof(stun_fingerprint_attr_t));
    if (fingerprint == NULL) return STUN_MEM_ERROR;

    fingerprint->hdr.type = STUN_ATTR_FINGERPRINT;

    /** store the position */
    fingerprint->position = pkt - buf_head - 2;

    memcpy(&val16, pkt, sizeof(uint16_t));
    fingerprint->hdr.length = ntohs(val16);
    pkt += 2;

    memcpy(&val32, pkt, sizeof(uint32_t));
    fingerprint->value = ntohl(val32);
    pkt += 4;

    *attr = (stun_attr_hdr_t *)fingerprint;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

#ifdef ENABLE_TURN

int32_t stun_attr_encode_channel_number(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_channel_number(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_channel_number_attr_t *channel;
    uint16_t val16;
    u_char *pkt = *buf;

    channel = (stun_channel_number_attr_t *) 
                stun_calloc (1, sizeof(stun_channel_number_attr_t));
    if (channel == NULL) return STUN_MEM_ERROR;

    channel->hdr.type = STUN_ATTR_CHANNEL_NUMBER;

    memcpy(&val16, pkt, sizeof(uint16_t));
    channel->hdr.length = ntohs(val16);
    pkt += 2;

    memcpy(&val16, buf, sizeof(uint16_t)); 
    channel->channel_number = ntohs(val16);
    pkt += 2;

    channel->rffu = 0;
    pkt += 2;

    /** TODO - move past the padded bytes? */

    *attr = (stun_attr_hdr_t *) channel;

    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_lifetime(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_lifetime(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_lifetime_attr_t *lifetime;
    uint16_t val16;
    uint32_t val32;
    u_char *pkt = *buf;

    lifetime = (stun_lifetime_attr_t *) 
                        stun_calloc (1, sizeof(stun_lifetime_attr_t));
    if (lifetime == NULL) return STUN_MEM_ERROR;

    lifetime->hdr.type = STUN_ATTR_LIFETIME;

    memcpy(&val16, pkt, sizeof(uint16_t));
    lifetime->hdr.length = ntohs(val16);
    pkt += 2;

    memcpy(&val32, pkt, sizeof(uint32_t));
    lifetime->lifetime = ntohl(val32);
    pkt += 4;

    /** TODO - move past the padded bytes? */

    *attr = (stun_attr_hdr_t *) lifetime;

    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_xor_peer_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_xor_peer_addr_attr_t *addr;
    uint16_t val16;
    u_char *hdr_len;

    addr = (stun_xor_peer_addr_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_XOR_PEER_ADDR);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    hdr_len = buf;
    buf += sizeof(uint16_t);

    /** empty byte */
    buf++;

    /** family */
    *buf = addr->family;
    buf++;

    /** port */
    val16 = addr->port ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    val16 = htons(val16);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** address */
    if(addr->family == STUN_ADDR_FAMILY_IPV4) {
        struct in_addr mapped_addr;
        uint32_t val32;

        if (inet_aton((char *)addr->address, &mapped_addr) == 0)
        {
            return STUN_INVALID_PARAMS;
        }
        mapped_addr.s_addr = ntohl(mapped_addr.s_addr);
        mapped_addr.s_addr ^= STUN_MAGIC_COOKIE;
        val32 = htonl(mapped_addr.s_addr);

        memcpy(buf, &val32, sizeof(uint32_t));
        buf += sizeof(uint32_t);
    } else {

        u_char xor_addr[16];
        uint32_t i;

        if (inet_pton(AF_INET6, (char *)addr->address, xor_addr) <= 0)
        {
            return STUN_INVALID_PARAMS;
        }

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        memcpy(buf, xor_addr, 16);
        buf += 16;
    }

    /** length */
    val16 = htons(buf - hdr_len - 2);
    memcpy(hdr_len, &val16, sizeof(uint16_t));

    /** no padding required */

    *len = buf - hdr_len + 2;

    return STUN_OK;
}


int32_t stun_attr_decode_xor_peer_address(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_xor_peer_addr_attr_t *addr;
    uint16_t val16, i;
    u_char *pkt = *buf;

    addr = (stun_xor_peer_addr_attr_t *) 
                        stun_calloc (1, sizeof(stun_xor_peer_addr_attr_t));
    if (addr == NULL) return STUN_MEM_ERROR;

    addr->hdr.type = STUN_ATTR_XOR_PEER_ADDR;

    memcpy(&val16, pkt, sizeof(uint16_t));
    addr->hdr.length = ntohs(val16);
    pkt += 2;

    /** skip one byte */
    pkt += 1;

    /** family */
    addr->family = *pkt;
    pkt += 1;

    /** port */
    memcpy(&val16, pkt, sizeof(uint16_t));
    val16 = ntohs(val16);
    addr->port = val16 ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    pkt += 2;

    if(addr->family == STUN_ADDR_FAMILY_IPV4) {

#if 1
        u_char xor_addr[4];
        memcpy(xor_addr, pkt, 4);

        for (i =0 ; i < 4; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
        {
            perror("inet_ntop: ");
        }
        pkt += 4;
#else
        struct in_addr peer_addr;
        uint32_t val32;
        memcpy(&val32, pkt, 4);
        peer_addr.s_addr = ntohl(val32);
        peer_addr.s_addr ^= STUN_MAGIC_COOKIE;
        peer_addr.s_addr = htonl(peer_addr.s_addr);
        pkt += 4;
        strncpy((char *)addr->address, 
                inet_ntoa(peer_addr), MAX_MAPPED_ADDRESS_LEN - 1);
#endif
    } else {

        u_char xor_addr[16];

        memcpy(xor_addr, pkt, 16);

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET6, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
            perror("inet_ntop: ");
        pkt += 16;
    }

    *attr = (stun_attr_hdr_t *) addr;

    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_data(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_data(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_xor_relayed_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_xor_relayed_addr_attr_t *addr;
    uint16_t val16;
    u_char *hdr_len;

    addr = (stun_xor_relayed_addr_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_XOR_RELAYED_ADDR);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    hdr_len = buf;
    buf += sizeof(uint16_t);

    /** empty byte */
    buf++;

    /** family */
    *buf = addr->family;
    buf++;

    /** port */
    val16 = addr->port ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    val16 = htons(val16);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** address */
    if(addr->family == STUN_ADDR_FAMILY_IPV4) {
        struct in_addr mapped_addr;
        uint32_t val32;

        if (inet_aton((char *)addr->address, &mapped_addr) == 0)
        {
            return STUN_INVALID_PARAMS;
        }
        mapped_addr.s_addr = ntohl(mapped_addr.s_addr);
        mapped_addr.s_addr ^= STUN_MAGIC_COOKIE;
        val32 = htonl(mapped_addr.s_addr);

        memcpy(buf, &val32, sizeof(uint32_t));
        buf += sizeof(uint32_t);
    } else {

        u_char xor_addr[16];
        uint32_t i;

        if (inet_pton(AF_INET6, (char *)addr->address, xor_addr) <= 0)
        {
            return STUN_INVALID_PARAMS;
        }

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        memcpy(buf, xor_addr, 16);
        buf += 16;
    }

    /** length */
    val16 = htons(buf - hdr_len - 2);
    memcpy(hdr_len, &val16, sizeof(uint16_t));

    /** no padding required */

    *len = buf - hdr_len + 2;

    return STUN_OK;
}


int32_t stun_attr_decode_xor_relayed_address(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_xor_relayed_addr_attr_t *addr;
    uint16_t val16, i;
    u_char *pkt = *buf;

    addr = (stun_xor_relayed_addr_attr_t *) 
                stun_calloc (1, sizeof(stun_xor_relayed_addr_attr_t));
    if (addr == NULL) return STUN_MEM_ERROR;

    addr->hdr.type = STUN_ATTR_XOR_RELAYED_ADDR;

    memcpy(&val16, pkt, sizeof(uint16_t));
    addr->hdr.length = ntohs(val16);
    pkt += 2;

    /** skip one byte */
    pkt += 1;

    /** family */
    addr->family = *pkt;
    pkt += 1;

    /** port */
    memcpy(&val16, pkt, sizeof(uint16_t));
    val16 = ntohs(val16);
    addr->port = val16 ^ STUN_XPORT_MAGC_COOKIE_BITMAP;
    pkt += 2;

    if(addr->family == STUN_ADDR_FAMILY_IPV4) {

#if 1
        u_char xor_addr[4];
        memcpy(xor_addr, pkt, 4);

        for (i =0 ; i < 4; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
        {
            perror("inet_ntop: ");
        }
        pkt += 4;
#else
        struct in_addr relayed_addr;
        uint32_t val32;
        memcpy(&val32, pkt, 4);
        relayed_addr.s_addr = ntohl(val32);
        relayed_addr.s_addr ^= STUN_MAGIC_COOKIE;
        relayed_addr.s_addr = htonl(relayed_addr.s_addr);
        pkt += 4;
        strncpy((char *)addr->address, 
                inet_ntoa(relayed_addr), MAX_MAPPED_ADDRESS_LEN - 1);
#endif
    } else {

        u_char xor_addr[16];

        memcpy(xor_addr, pkt, 16);

        /** xor byte by byte with (magic_cookie + txn_id) */
        for (i =0 ; i < 16; i++)
            xor_addr[i] ^= *(buf_head+4+i);

        if (inet_ntop(AF_INET6, xor_addr, 
                    (char *)addr->address, MAX_MAPPED_ADDRESS_LEN) == NULL)
            perror("inet_ntop: ");
        pkt += 16;
    }

    *attr = (stun_attr_hdr_t *) addr;

    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_even_port(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_even_port(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_requested_transport(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_req_transport_attr_t *tport;
    uint16_t val16;

    tport = (stun_req_transport_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_REQUESTED_TRANSPORT);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    val16 = htons(tport->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    *buf = tport->protocol;

    *len = tport->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_requested_transport(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_dont_fragment(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_dont_fragment(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_reservation_token(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {
    return STUN_OK;
}


int32_t stun_attr_decode_reservation_token(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {
    return STUN_OK;
}

/*============================================================================*/
#endif

#ifdef ENABLE_ICE
/*============================================================================*/

int32_t stun_attr_encode_priority(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_priority_attr_t *priority;
    uint16_t val16;
    uint32_t val32;

    priority = (stun_priority_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_PRIORITY);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute length */
    val16 = htons(priority->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute value */
    val32 = htonl(priority->priority);
    stun_memcpy(buf, &val32, sizeof(uint32_t));
    buf += sizeof(uint32_t);

    *len = priority->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_priority(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_priority_attr_t *priority;
    uint16_t val16;
    u_char *pkt = *buf;
    uint32_t val32;

    priority = (stun_priority_attr_t *) 
                        stun_calloc (1, sizeof(stun_priority_attr_t));
    if (priority == NULL) return STUN_MEM_ERROR;

    priority->hdr.type = STUN_ATTR_PRIORITY;

    memcpy(&val16, pkt, sizeof(uint16_t));
    priority->hdr.length = ntohs(val16);
    pkt += 2;

    memcpy(&val32, pkt, sizeof(uint32_t));
    priority->priority = ntohl(val32);
    pkt += 4;

    *attr = (stun_attr_hdr_t *)priority;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_use_candidate(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_use_candidate_attr_t *use_cand;
    uint16_t val16;

    use_cand = (stun_use_candidate_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_USE_CANDIDATE);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute length */
    val16 = htons(use_cand->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    *len = use_cand->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_use_candidate(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_use_candidate_attr_t *use_cand;
    uint16_t val16;
    u_char *pkt = *buf;

    use_cand = (stun_use_candidate_attr_t *) 
                        stun_calloc (1, sizeof(stun_use_candidate_attr_t));
    if (use_cand == NULL) return STUN_MEM_ERROR;

    use_cand->hdr.type = STUN_ATTR_USE_CANDIDATE;

    memcpy(&val16, pkt, sizeof(uint16_t));
    use_cand->hdr.length = ntohs(val16);
    pkt += 2;

    *attr = (stun_attr_hdr_t *)use_cand;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_ice_controlled(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_ice_controlled_attr_t *controlled;
    uint16_t val16;
    uint32_t val32[2];

    controlled = (stun_ice_controlled_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_ICE_CONTROLLED);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute length */
    val16 = htons(controlled->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute value */
    val32[0] = htonl((uint32_t)(controlled->random_num >> 32));
    val32[1] = htonl((uint32_t) controlled->random_num);
    stun_memcpy(buf, val32, sizeof(uint64_t));
    buf += sizeof(uint64_t);

    *len = controlled->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_ice_controlled(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_ice_controlled_attr_t *controlled;
    uint16_t val16;
    u_char *pkt = *buf;
    uint32_t val32[2];

    controlled = (stun_ice_controlled_attr_t*) 
                stun_calloc (1, sizeof(stun_ice_controlled_attr_t));
    if (controlled == NULL) return STUN_MEM_ERROR;

    controlled->hdr.type = STUN_ATTR_ICE_CONTROLLED;

    memcpy(&val16, pkt, sizeof(uint16_t));
    controlled->hdr.length = ntohs(val16);
    pkt += 2;

    stun_memcpy(val32, pkt, sizeof(uint64_t));
    controlled->random_num = ((uint64_t) ntohl(val32[0]) << 32) | ntohl(val32[1]);
    pkt += sizeof(uint64_t);

    *attr = (stun_attr_hdr_t *)controlled;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

int32_t stun_attr_encode_ice_controlling(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len) {

    stun_ice_controlling_attr_t *controlling;
    uint16_t val16;
    uint32_t val32[2];

    controlling = (stun_ice_controlling_attr_t *) attr;

    /** attribute type */
    val16 = htons(STUN_ATTR_ICE_CONTROLLING);
    stun_memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute length */
    val16 = htons(controlling->hdr.length);
    memcpy(buf, &val16, sizeof(uint16_t));
    buf += sizeof(uint16_t);

    /** attribute value */
    val32[0] = htonl((uint32_t)(controlling->random_num >> 32));
    val32[1] = htonl((uint32_t) controlling->random_num);
    stun_memcpy(buf, val32, sizeof(uint64_t));
    buf += sizeof(uint64_t);

    *len = controlling->hdr.length + 4;

    return STUN_OK;
}


int32_t stun_attr_decode_ice_controlling(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_ice_controlling_attr_t *controlling;
    uint16_t val16;
    u_char *pkt = *buf;
    uint32_t val32[2];

    controlling = (stun_ice_controlling_attr_t*) 
                stun_calloc (1, sizeof(stun_ice_controlling_attr_t));
    if (controlling == NULL) return STUN_MEM_ERROR;

    controlling->hdr.type = STUN_ATTR_ICE_CONTROLLING;

    memcpy(&val16, pkt, sizeof(uint16_t));
    controlling->hdr.length = ntohs(val16);
    pkt += 2;

    stun_memcpy(val32, pkt, sizeof(uint64_t));
    controlling->random_num = ((uint64_t) ntohl(val32[0]) << 32) | ntohl(val32[1]);
    pkt += sizeof(uint64_t);

    *attr = (stun_attr_hdr_t *)controlling;
    *buf = pkt;

    return STUN_OK;
}

/*============================================================================*/

#endif

/*============================================================================*/

int32_t stun_attr_decode_extended_attr(uint16_t attr_type, 
                                u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr) {

    stun_extended_attr_t *ext_attr;
    uint16_t val16;
    u_char *pkt = *buf;

    ext_attr = (stun_extended_attr_t *) 
                        stun_calloc (1, sizeof(stun_extended_attr_t));
    if (ext_attr == NULL) return STUN_MEM_ERROR;

    if (attr_type <= COMP_REQUIRED_RANGE_MAX)
        ext_attr->hdr.type = STUN_ATTR_UNKNOWN_COMP_REQUIRED;
    else
        ext_attr->hdr.type = STUN_ATTR_UNKNOWN_COMP_OPTIONAL;

    ext_attr->attr_type_value = attr_type;

    memcpy(&val16, pkt, sizeof(uint16_t));
    ext_attr->hdr.length = ntohs(val16);
    pkt += 2;

    if (ext_attr->hdr.length > STUN_EXT_ATTR_VALUE_LEN)
        ext_attr->hdr.length = STUN_EXT_ATTR_VALUE_LEN;

    memcpy(ext_attr->value, pkt, ext_attr->hdr.length);
    pkt +=  ext_attr->hdr.length;

    *attr = (stun_attr_hdr_t *)ext_attr;
    *buf = pkt;

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
