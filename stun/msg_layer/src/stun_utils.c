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

#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_utils.h"


handle stun_utils_create_attr(stun_attribute_type_t attr_type)
{
    handle attr = NULL;
    uint32_t size = 0;

    switch(attr_type)
    {
        case STUN_ATTR_MAPPED_ADDR:
            size = sizeof(stun_mapped_addr_attr_t);
            break;

        case STUN_ATTR_USERNAME:
            size = sizeof(stun_username_attr_t);
            break;

        case STUN_ATTR_MESSAGE_INTEGRITY:
            size = sizeof(stun_msg_integrity_attr_t);
            break;

        case STUN_ATTR_ERROR_CODE:
            size = sizeof(stun_error_code_attr_t);
            break;

        case STUN_ATTR_UNKNOWN_ATTRIBUTES:
            /** size = sizeof(); */
            break;

        case STUN_ATTR_REALM:
            size = sizeof(stun_realm_attr_t);
            break;

        case STUN_ATTR_NONCE:
            size = sizeof(stun_nonce_attr_t);
            break;

        case STUN_ATTR_XOR_MAPPED_ADDR:
            size = sizeof(stun_xor_mapped_addr_attr_t);
            break;

        case STUN_ATTR_SOFTWARE:
            size = sizeof(stun_software_attr_t);
            break;

        case STUN_ATTR_ALTERNATE_SERVER:
            size = sizeof(stun_alt_server_attr_t);
            break;

        case STUN_ATTR_FINGERPRINT:
            size = sizeof(stun_fingerprint_attr_t);
            break;

#ifdef MB_ENABLE_TURN
        case STUN_ATTR_CHANNEL_NUMBER:
            size = sizeof(stun_channel_number_attr_t);
            break;

        case STUN_ATTR_LIFETIME:
            size = sizeof(stun_lifetime_attr_t);
            break;

        case STUN_ATTR_XOR_PEER_ADDR:
            size = sizeof(stun_xor_peer_addr_attr_t);
            break;

        case STUN_ATTR_DATA:
            size = sizeof(stun_data_attr_t);
            break;

        case STUN_ATTR_XOR_RELAYED_ADDR:
            size = sizeof(stun_xor_relayed_addr_attr_t);
            break;

        case STUN_ATTR_EVEN_PORT:
            size = sizeof(stun_even_port_attr_t);
            break;

        case STUN_ATTR_REQUESTED_TRANSPORT:
            size = sizeof(stun_req_transport_attr_t);
            break;

        case STUN_ATTR_DONT_FRAGMENT:
            size = sizeof(stun_dont_fragment_attr_t);
            break;

        case STUN_ATTR_RESERVATION_TOKEN:
            size = sizeof(stun_reservation_token_attr_t);
            break;

#endif
#ifdef MB_ENABLE_ICE

        case STUN_ATTR_PRIORITY:
            size = sizeof(stun_priority_attr_t);
            break;

        case STUN_ATTR_USE_CANDIDATE:
            size = sizeof(stun_use_candidate_attr_t);
            break;

        case STUN_ATTR_ICE_CONTROLLED:
        case STUN_ATTR_ICE_CONTROLLING:
            size = sizeof(stun_ice_controlled_attr_t);
            break;

#endif

        default:
            break;
    }

    if (size)
        attr = (handle) stun_calloc(1, size);

    return attr;
}



int32_t stun_utils_destroy_attr(handle stun_attr)
{
    stun_attr_hdr_t *attr = (stun_attr_hdr_t *) stun_attr;
    switch(attr->type)
    {
        case STUN_ATTR_MAPPED_ADDR:
        case STUN_ATTR_MESSAGE_INTEGRITY:
            stun_free(attr);
            break;

        case STUN_ATTR_UNKNOWN_ATTRIBUTES:
            return STUN_INT_ERROR;
            break;

        case STUN_ATTR_ERROR_CODE:
        {
            stun_error_code_attr_t *error_code = (stun_error_code_attr_t *) stun_attr;
            stun_free(error_code->reason);
            stun_free(error_code);
        }
        break;

        case STUN_ATTR_USERNAME:
        {
            stun_username_attr_t *name = (stun_username_attr_t *) stun_attr;
            stun_free(name->username);
            stun_free(name);
        }
        break;

        case STUN_ATTR_SOFTWARE:
        {
            stun_software_attr_t *sft = (stun_software_attr_t *) stun_attr;
            stun_free(sft->software);
            stun_free(sft);
        }
        break;

        case STUN_ATTR_REALM:
        {
            stun_realm_attr_t *realm = (stun_realm_attr_t *) stun_attr;
            stun_free(realm->realm);
            stun_free(realm);
        }
        break;

        case STUN_ATTR_NONCE:
        {
            stun_nonce_attr_t *nonce = (stun_nonce_attr_t *) stun_attr;
            stun_free(nonce->nonce);
            stun_free(nonce);
        }
        break;

        case STUN_ATTR_XOR_MAPPED_ADDR:
        case STUN_ATTR_ALTERNATE_SERVER:
        case STUN_ATTR_FINGERPRINT:
            stun_free(attr);
            break;

#ifdef MB_ENABLE_TURN
        case STUN_ATTR_DATA:
        {
            stun_data_attr_t *data = (stun_data_attr_t *) stun_attr;
            stun_free(data->data);
            stun_free(data);
        }
        break;

        case STUN_ATTR_CHANNEL_NUMBER:
        case STUN_ATTR_LIFETIME:
        case STUN_ATTR_XOR_PEER_ADDR:
        case STUN_ATTR_XOR_RELAYED_ADDR:
        case STUN_ATTR_EVEN_PORT:
        case STUN_ATTR_REQUESTED_TRANSPORT:
        case STUN_ATTR_DONT_FRAGMENT:
        case STUN_ATTR_RESERVATION_TOKEN:
#endif
#ifdef MB_ENABLE_ICE

        case STUN_ATTR_PRIORITY:
        case STUN_ATTR_USE_CANDIDATE:
        case STUN_ATTR_ICE_CONTROLLED:
        case STUN_ATTR_ICE_CONTROLLING:
#endif
        case STUN_ATTR_UNKNOWN_COMP_OPTIONAL:
        case STUN_ATTR_UNKNOWN_COMP_REQUIRED:
            stun_free(attr);
            break;

        default:
            break;
    }

    return STUN_OK;
}


int32_t stun_msg_utils_add_unknown_attributes(
                            handle h_msg, handle *pah_attr, uint32_t num)
{
    int32_t status, i;
    handle h_attr;
    uint16_t attr_type;

    if ((h_msg == NULL) || (pah_attr == NULL) || (num <= 0))
        return STUN_INVALID_PARAMS;

    status = stun_attr_create(STUN_ATTR_UNKNOWN_ATTRIBUTES, &h_attr);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Error while creating STUN_ATTR_UNKNOWN_ATTRIBUTES attribute");
        return status;
    }

    for (i = 0; i < num; i++)
    {
        status = stun_extended_attr_get_attr_type(pah_attr, &attr_type);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Error while getting attribute type value from "\
                    "extended attribute");
            goto ERROR_EXIT;
        }

        status = stun_attr_unknown_attributes_add_attr_type(h_attr, attr_type);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Unable to add unknown attribute type to unknown-attributes");
            goto ERROR_EXIT;
        }
    }

    /** now add the attribute to the message */
    status = stun_msg_add_attribute(h_msg, h_attr);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of UNKNOWN-ATTRIBUTES attribute to message failed");
        goto ERROR_EXIT;
    }

    return STUN_OK;

ERROR_EXIT:
    
    stun_attr_destroy(h_attr);

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
