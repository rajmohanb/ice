/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
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



int32_t stun_attr_create(stun_attribute_type_t attr_type, handle *h_attr)
{
    stun_attr_hdr_t *attr;

    if ((h_attr == NULL) || (attr_type >= STUN_ATTR_MAX))
        return STUN_INVALID_PARAMS;

    attr = (stun_attr_hdr_t *)stun_utils_create_attr(attr_type);
    if (attr == NULL) return STUN_INT_ERROR;

    attr->type = (uint16_t) attr_type;
    attr->length = 0;

    *h_attr = (handle)attr;

    return STUN_OK;
}


int32_t stun_attr_destroy(handle h_attr)
{
    if (h_attr == NULL)
        return STUN_INVALID_PARAMS;

    return stun_utils_destroy_attr(h_attr);
}


int32_t stun_attr_software_set_value(handle h_attr, u_char *value, uint16_t len)
{
    stun_software_attr_t *attr;

    if ((value == NULL) || (h_attr == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_software_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_SOFTWARE)
        return STUN_INVALID_PARAMS;

    if (len > MAX_SOFTWARE_VAL_BYTES) return STUN_INVALID_PARAMS;

    attr->software = stun_calloc(1, len);
    if (attr->software == NULL) return STUN_MEM_ERROR;

    stun_memcpy(attr->software, value, len);

    attr->hdr.length = len;

    return STUN_OK;
}


int32_t stun_attr_software_get_value_length(handle h_attr, uint32_t *len)
{
    stun_software_attr_t *vendor;

    if ((h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    vendor = (stun_software_attr_t *) h_attr;

    if (vendor->hdr.type != STUN_ATTR_SOFTWARE)
        return STUN_INVALID_PARAMS;

    *len = vendor->hdr.length;

    return STUN_OK;
}



int32_t stun_attr_software_get_value(handle h_attr, 
                                        u_char *value, uint16_t *len)
{
    stun_software_attr_t *attr;

    if ((value == NULL) || (h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_software_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_SOFTWARE)
        return STUN_INVALID_PARAMS;

    if (*len < attr->hdr.length)
    { 
        *len = attr->hdr.length;
        return STUN_MEM_INSUF;
    }

    stun_memcpy(value, attr->software, attr->hdr.length);
    *len = attr->hdr.length;

    return STUN_OK;
}



int32_t stun_attr_mapped_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len)
{
    stun_mapped_addr_attr_t *attr;
    uint32_t size;

    if ((address == NULL) || (h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    *addr_family = attr->family;

    if (attr->family == STUN_ADDR_FAMILY_IPV4)
    {
        size = *len - 1;
        stun_strncpy((char *)address, (char *)attr->address, size);
        *len = size;
    }
    else
    {
        stun_strncpy((char *)address, (char *)attr->address, 16);
        *len = 16;
    }

    return STUN_OK;
}


int32_t stun_attr_mapped_addr_get_port(handle h_attr, uint32_t *port)
{
    stun_mapped_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    *port = attr->port;

    return STUN_OK;
}


int32_t stun_attr_xor_mapped_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len)
{
    stun_xor_mapped_addr_attr_t *attr;
    uint32_t size;

    if ((address == NULL) || (h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    *addr_family = attr->family;

    if (attr->family == STUN_ADDR_FAMILY_IPV4)
    {
        size = *len - 1;
        stun_strncpy((char *)address, (char *)attr->address, size);
        *len = size;
    }
    else
    {
        stun_strncpy((char *)address, 
                (char *)attr->address, MAX_MAPPED_ADDRESS_LEN - 1);
        *len = MAX_MAPPED_ADDRESS_LEN;
    }

    return STUN_OK;
}


int32_t stun_attr_xor_mapped_addr_set_address(handle h_attr, 
            u_char *address, uint32_t len, stun_addr_family_type_t family)
{
    stun_xor_mapped_addr_attr_t *attr;

    if ((address == NULL) || (h_attr == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    attr->family = family;
    stun_strncpy((char *)attr->address, (char *)address, len);

    /** 
     * length includes 2 bytes for port, 1 byte for 
     * representing family and 1 dummy byte.
     */
    if (family == STUN_ADDR_FAMILY_IPV4)
        attr->hdr.length = STUN_IPV4_FAMILY_SIZE+4;
    else
        attr->hdr.length = STUN_IPV6_FAMILY_SIZE+4;

    return STUN_OK;
}


int32_t stun_attr_xor_mapped_addr_get_port(handle h_attr, uint32_t *port)
{
    stun_xor_mapped_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    *port = attr->port;

    return STUN_OK;
}


int32_t stun_attr_xor_mapped_addr_set_port(handle h_attr, uint32_t port)
{
    stun_xor_mapped_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_MAPPED_ADDR)
        return STUN_INVALID_PARAMS;

    attr->port = port;

    return STUN_OK;
}


#ifdef MB_ENABLE_TURN
int32_t stun_attr_xor_relayed_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len)
{
    stun_mapped_addr_attr_t *attr;
    uint32_t size;

    if ((address == NULL) || (h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_mapped_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_RELAYED_ADDR)
        return STUN_INVALID_PARAMS;

    *addr_family = attr->family;

    if (attr->family == STUN_ADDR_FAMILY_IPV4)
    {
        size = *len - 1;
        stun_strncpy((char *)address, (char *)attr->address, size);
        *len = size;
    }
    else
    {
        stun_strncpy((char *)address, (char *)attr->address, 16);
        *len = 16;
    }

    return STUN_OK;
}

int32_t stun_attr_xor_relayed_addr_get_port(handle h_attr, uint32_t *port)
{
    stun_xor_relayed_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_relayed_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_RELAYED_ADDR)
        return STUN_INVALID_PARAMS;

    *port = attr->port;

    return STUN_OK;
}



int32_t stun_attr_xor_peer_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len)
{
    stun_xor_peer_addr_attr_t *attr;
    uint32_t size;

    if ((address == NULL) || (h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_peer_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_PEER_ADDR)
        return STUN_INVALID_PARAMS;

    *addr_family = attr->family;

    if (attr->family == STUN_ADDR_FAMILY_IPV4)
    {
        size = *len - 1;
        stun_strncpy((char *)address, (char *)attr->address, size);
        *len = size;
    }
    else
    {
        stun_strncpy((char *)address, 
                (char *)attr->address, MAX_MAPPED_ADDRESS_LEN - 1);
        *len = MAX_MAPPED_ADDRESS_LEN;
    }

    return STUN_OK;
}


int32_t stun_attr_xor_peer_addr_set_address(handle h_attr, 
            u_char *address, uint32_t len, stun_addr_family_type_t family)
{
    stun_xor_peer_addr_attr_t *attr;

    if ((address == NULL) || (h_attr == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_peer_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_PEER_ADDR)
        return STUN_INVALID_PARAMS;

    attr->family = family;

    if (family == STUN_ADDR_FAMILY_IPV4)
    {
        stun_strncpy((char *)attr->address, (char *)address, len);
    }
    else
    {
        stun_strncpy((char *)attr->address, (char *)address, len);
    }

    return STUN_OK;
}


int32_t stun_attr_xor_peer_addr_get_port(handle h_attr, uint32_t *port)
{
    stun_xor_peer_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_peer_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_PEER_ADDR)
        return STUN_INVALID_PARAMS;

    *port = attr->port;

    return STUN_OK;
}


int32_t stun_attr_xor_peer_addr_set_port(handle h_attr, uint32_t port)
{
    stun_xor_peer_addr_attr_t *attr;

    if ((h_attr == NULL) || (port == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_xor_peer_addr_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_XOR_PEER_ADDR)
        return STUN_INVALID_PARAMS;

    attr->port = port;

    return STUN_OK;
}


int32_t stun_attr_lifetime_get_duration(handle h_attr, uint32_t *duration)
{
    stun_lifetime_attr_t *attr;

    if ((h_attr == NULL) || (duration == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_lifetime_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_LIFETIME)
        return STUN_INVALID_PARAMS;

    *duration = attr->lifetime;

    return STUN_OK;
}


int32_t stun_attr_lifetime_set_duration(handle h_attr, uint32_t duration)
{
    stun_lifetime_attr_t *attr;

    if (h_attr == NULL) return STUN_INVALID_PARAMS;

    attr = (stun_lifetime_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_LIFETIME)
        return STUN_INVALID_PARAMS;

    attr->lifetime = duration;

    return STUN_OK;
}


int32_t stun_attr_data_get_data_length(handle h_attr, uint32_t *len)
{
    stun_data_attr_t *attr;

    if ((h_attr == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    attr = (stun_data_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_DATA)
        return STUN_INVALID_PARAMS;

    *len = attr->length;

    return STUN_OK;
}


int32_t stun_attr_data_get_data(handle h_attr, u_char *data, uint32_t len)
{
    stun_data_attr_t *attr;

    if ((h_attr == NULL) || (data == NULL))
        return STUN_INVALID_PARAMS;

    attr = (stun_data_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_DATA)
        return STUN_INVALID_PARAMS;

    if(attr->length > len) return STUN_MEM_INSUF;

    stun_memcpy(data, attr->data, attr->length);

    return STUN_OK;
}


int32_t stun_attr_data_set_data(handle h_attr, u_char *data, uint32_t len)
{
    stun_data_attr_t *attr;

    if (h_attr == NULL) return STUN_INVALID_PARAMS;
    /** data of length zero is perfectly legal! */

    attr = (stun_data_attr_t *) h_attr;

    if (attr->hdr.type != STUN_ATTR_DATA)
        return STUN_INVALID_PARAMS;

    attr->data = (u_char *) stun_calloc (1, len);
    if (attr->data == NULL) return STUN_MEM_ERROR;

    stun_memcpy(attr->data, data, len);
    attr->length = len;

    return STUN_OK;
}



#endif


int32_t stun_attr_error_code_get_error_code(handle h_attr, uint32_t *code)
{
    stun_error_code_attr_t *error_code;

    if ((h_attr == NULL) || (code == NULL))
        return STUN_INVALID_PARAMS;

    error_code = (stun_error_code_attr_t *) h_attr;

    if (error_code->hdr.type != STUN_ATTR_ERROR_CODE)
        return STUN_INVALID_PARAMS;

    *code = error_code->code;

    return STUN_OK;
}


int32_t stun_attr_error_code_set_error_code(handle h_attr, uint32_t code)
{
    stun_error_code_attr_t *error_code;

    if ((h_attr == NULL) || (code == 0))
        return STUN_INVALID_PARAMS;

    error_code = (stun_error_code_attr_t *) h_attr;

    if (error_code->hdr.type != STUN_ATTR_ERROR_CODE)
        return STUN_INVALID_PARAMS;

    error_code->code = code;

    return STUN_OK;
}


int32_t stun_attr_error_code_set_error_reason(
                            handle h_attr, char *reason, uint32_t len)
{
    stun_error_code_attr_t *error_code;

    if ((h_attr == NULL) || (reason == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    error_code = (stun_error_code_attr_t *) h_attr;

    if (error_code->hdr.type != STUN_ATTR_ERROR_CODE)
        return STUN_INVALID_PARAMS;

    if (len > MAX_ERROR_CODE_REASON_BYTES) return STUN_INVALID_PARAMS;

    error_code->reason = stun_calloc(1, len);
    if (error_code->reason == NULL) return STUN_MEM_ERROR;

    stun_memcpy(error_code->reason, reason, len);
    error_code->hdr.length = len + 4; /** 4 bytes for error code */

    return STUN_OK;
}



int32_t stun_attr_username_get_username_length(handle h_attr, uint32_t *len)
{
    stun_username_attr_t *name;

    if ((h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    name = (stun_username_attr_t *) h_attr;

    if (name->hdr.type != STUN_ATTR_USERNAME)
        return STUN_INVALID_PARAMS;

    *len = name->hdr.length;

    return STUN_OK;
}



int32_t stun_attr_username_get_username(
                    handle h_attr, u_char *username, uint32_t *len)
{
    stun_username_attr_t *name;

    if ((h_attr == NULL) || (username == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    name = (stun_username_attr_t *) h_attr;

    if (name->hdr.type != STUN_ATTR_USERNAME)
        return STUN_INVALID_PARAMS;

    if (*len < name->hdr.length)
    {
        *len = name->hdr.length;
        return STUN_MEM_INSUF;
    }

    stun_memcpy(username, name->username, name->hdr.length);
    *len = name->hdr.length;

    return STUN_OK;
}


int32_t stun_attr_username_set_username(handle h_attr, 
                                                u_char *name, uint32_t len)
{
    stun_username_attr_t *username;

    if ((h_attr == NULL) || (name == NULL))
        return STUN_INVALID_PARAMS;

    username = (stun_username_attr_t *) h_attr;

    if (username->hdr.type != STUN_ATTR_USERNAME)
        return STUN_INVALID_PARAMS;

    if (len > MAX_USERNAME_LEN) return STUN_INVALID_PARAMS;

    username->username = stun_calloc(1, len);
    if (username->username == NULL) return STUN_MEM_ERROR;

    stun_memcpy(username->username, name, len);
    username->hdr.length = len;

    return STUN_OK;

}


int32_t stun_attr_nonce_get_nonce_length(handle h_attr, uint32_t *len)
{
    stun_nonce_attr_t *nonce;

    if ((h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    nonce = (stun_nonce_attr_t *) h_attr;

    if (nonce->hdr.type != STUN_ATTR_NONCE)
        return STUN_INVALID_PARAMS;

    *len = nonce->hdr.length;

    return STUN_OK;
}


int32_t stun_attr_nonce_get_nonce(handle h_attr, 
                                        u_char *nonce_val, uint32_t *len)
{
    stun_nonce_attr_t *nonce;

    if ((h_attr == NULL) || (nonce_val == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    nonce = (stun_nonce_attr_t *) h_attr;

    if (nonce->hdr.type != STUN_ATTR_NONCE)
        return STUN_INVALID_PARAMS;

    if (*len < nonce->hdr.length)
    {
        *len = nonce->hdr.length;
        return STUN_MEM_INSUF;
    }

    stun_memcpy(nonce_val, nonce->nonce, nonce->hdr.length);
    *len = nonce->hdr.length;

    return STUN_OK;
}


int32_t stun_attr_nonce_set_nonce(handle h_attr, 
                                        u_char *nonce_val, uint32_t len)
{
    stun_nonce_attr_t *nonce;

    if ((h_attr == NULL) || (nonce_val == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    nonce = (stun_nonce_attr_t *) h_attr;

    if (nonce->hdr.type != STUN_ATTR_NONCE)
        return STUN_INVALID_PARAMS;

    if (len > MAX_NONCE_VAL_BYTES) return STUN_INVALID_PARAMS;

    nonce->nonce = stun_calloc(1, len);
    if (nonce->nonce == NULL) return STUN_MEM_ERROR;

    stun_memcpy(nonce->nonce, nonce_val, len);
    nonce->hdr.length = len;

    return STUN_OK;
}



int32_t stun_attr_realm_get_realm_length(handle h_attr, uint32_t *len)
{
    stun_realm_attr_t *realm;

    if ((h_attr == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    realm = (stun_realm_attr_t *) h_attr;

    if (realm->hdr.type != STUN_ATTR_REALM)
        return STUN_INVALID_PARAMS;

    *len = realm->hdr.length;

    return STUN_OK;
}



int32_t stun_attr_realm_get_realm(handle h_attr, 
                                        u_char *realm_val, uint32_t *len)
{
    stun_realm_attr_t *realm;

    if ((h_attr == NULL) || (realm_val == NULL) || (len == NULL))
        return STUN_INVALID_PARAMS;

    realm = (stun_realm_attr_t *) h_attr;

    if (realm->hdr.type != STUN_ATTR_REALM)
        return STUN_INVALID_PARAMS;

    if (*len < realm->hdr.length)
    {
        *len = realm->hdr.length;
        return STUN_MEM_INSUF;
    }

    stun_memcpy(realm_val, realm->realm, realm->hdr.length);
    *len = realm->hdr.length;

    return STUN_OK;
}



int32_t stun_attr_realm_set_realm(handle h_attr, 
                                        u_char *realm_val, uint32_t len)
{
    stun_realm_attr_t *realm;

    if ((h_attr == NULL) || (realm_val == NULL) || (len == 0))
        return STUN_INVALID_PARAMS;

    realm = (stun_realm_attr_t *) h_attr;

    if (realm->hdr.type != STUN_ATTR_REALM)
        return STUN_INVALID_PARAMS;

    if (len > MAX_REALM_VAL_BYTES) return STUN_INVALID_PARAMS;

    realm->realm = stun_calloc(1, len);
    if (realm->realm == NULL) return STUN_MEM_ERROR;

    stun_memcpy(realm->realm, realm_val, len);
    realm->hdr.length = len;

    return STUN_OK;
}



int32_t stun_attr_unknown_attributes_add_attr_type(
                                        handle h_attr, uint16_t attr_type)
{
    stun_unknown_attributes_attr_t *unknown_attr;

    if ((h_attr == NULL) || (attr_type == 0))
        return STUN_INVALID_PARAMS;

    unknown_attr = (stun_unknown_attributes_attr_t *) h_attr;

    if (unknown_attr->hdr.type != STUN_ATTR_UNKNOWN_ATTRIBUTES)
        return STUN_INVALID_PARAMS;

    if (unknown_attr->count == MAX_UNKNOWN_ATTRIBUTE_TYPES)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Maximum configured unknown attribute types reached");
        return STUN_INVALID_PARAMS;
    }

    unknown_attr->attr_types[unknown_attr->count] = attr_type;
    unknown_attr->count += 1;

    return STUN_OK;
}


int32_t stun_extended_attr_get_attr_type(handle h_attr, uint16_t *attr_type)
{
    stun_extended_attr_t *ext_attr;

    if ((h_attr == NULL) || (attr_type == NULL))
        return STUN_INVALID_PARAMS;

    ext_attr = (stun_extended_attr_t *) h_attr;

    if ((ext_attr->hdr.type != STUN_ATTR_UNKNOWN_COMP_OPTIONAL) &&
        (ext_attr->hdr.type != STUN_ATTR_UNKNOWN_COMP_REQUIRED))
        return STUN_INVALID_PARAMS;

    *attr_type = ext_attr->attr_type_value;

    return STUN_OK;
}


#ifdef MB_ENABLE_TURN

int32_t stun_attr_requested_transport_set_protocol(
                        handle h_attr, stun_transport_protocol_type_t proto)
{
    stun_req_transport_attr_t *tport;

    if (h_attr == NULL) return STUN_INVALID_PARAMS;

    tport = (stun_req_transport_attr_t *) h_attr;

    if (tport->hdr.type != STUN_ATTR_REQUESTED_TRANSPORT)
        return STUN_INVALID_PARAMS;

    if ((proto != STUN_TRANSPORT_TCP) && 
            (proto != STUN_TRANSPORT_UDP) && (proto != STUN_TRANSPORT_SCTP))
        return STUN_INVALID_PARAMS;

    tport->protocol = proto;
    tport->hdr.length = 4;

    return STUN_OK;
}


int32_t stun_attr_channel_number_set_channel(handle h_attr, uint16_t num)
{
    stun_channel_number_attr_t *chnl = (stun_channel_number_attr_t *) h_attr;

    if (h_attr == NULL) return STUN_INVALID_PARAMS;

    if (chnl->hdr.type != STUN_ATTR_CHANNEL_NUMBER)
        return STUN_INVALID_PARAMS;

    chnl->channel_number = num;
    chnl->hdr.length = 2;

    return STUN_OK;
}

#endif


#ifdef MB_ENABLE_ICE

int32_t stun_attr_priority_get_priority(handle h_attr, uint32_t *priority)
{
    stun_priority_attr_t *prio;

    if ((h_attr == NULL) || (priority == NULL))
        return STUN_INVALID_PARAMS;

    prio = (stun_priority_attr_t *) h_attr;

    if (prio->hdr.type != STUN_ATTR_PRIORITY)
        return STUN_INVALID_PARAMS;

    *priority = prio->priority;

    return STUN_OK;
}


int32_t stun_attr_priority_set_priority(handle h_attr, uint32_t priority)
{
    stun_priority_attr_t *prio;

    if ((h_attr == NULL) || (priority == 0))
        return STUN_INVALID_PARAMS;

    prio = (stun_priority_attr_t *) h_attr;

    if (prio->hdr.type != STUN_ATTR_PRIORITY)
        return STUN_INVALID_PARAMS;

    prio->priority = priority;
    prio->hdr.length = 4;

    return STUN_OK;
}


int32_t stun_attr_ice_controlling_get_tiebreaker_value(
                                            handle h_attr, uint64_t *tiebreak)
{
    stun_ice_controlling_attr_t *controlling;

    if ((h_attr == NULL) || (tiebreak == NULL))
        return STUN_INVALID_PARAMS;

    controlling = (stun_ice_controlling_attr_t *) h_attr;

    if (controlling->hdr.type != STUN_ATTR_ICE_CONTROLLING)
        return STUN_INVALID_PARAMS;

    *tiebreak = controlling->random_num;

    return STUN_OK;
}


int32_t stun_attr_ice_controlling_set_tiebreaker_value(
                                            handle h_attr, uint64_t tiebreak)
{
    stun_ice_controlling_attr_t *controlling;

    if ((h_attr == NULL) || (tiebreak == 0))
        return STUN_INVALID_PARAMS;

    controlling = (stun_ice_controlling_attr_t *) h_attr;

    if (controlling->hdr.type != STUN_ATTR_ICE_CONTROLLING)
        return STUN_INVALID_PARAMS;

    controlling->random_num = tiebreak;
    controlling->hdr.length = 8;

    return STUN_OK;
}


int32_t stun_attr_ice_controlled_get_tiebreaker_value(
                                            handle h_attr, uint64_t *tiebreak)
{
    stun_ice_controlled_attr_t *controlled;

    if ((h_attr == NULL) || (tiebreak == NULL))
        return STUN_INVALID_PARAMS;

    controlled = (stun_ice_controlled_attr_t *) h_attr;

    if (controlled->hdr.type != STUN_ATTR_ICE_CONTROLLED)
        return STUN_INVALID_PARAMS;

    *tiebreak = controlled->random_num;

    return STUN_OK;
}


int32_t stun_attr_ice_controlled_set_tiebreaker_value(
                                            handle h_attr, uint64_t tiebreak)
{
    stun_ice_controlled_attr_t *controlled;

    if ((h_attr == NULL) || (tiebreak == 0))
        return STUN_INVALID_PARAMS;

    controlled = (stun_ice_controlled_attr_t *) h_attr;

    if (controlled->hdr.type != STUN_ATTR_ICE_CONTROLLED)
        return STUN_INVALID_PARAMS;

    controlled->random_num = tiebreak;
    controlled->hdr.length = 8;

    return STUN_OK;
}


#endif


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
