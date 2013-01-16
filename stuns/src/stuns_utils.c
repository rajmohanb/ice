/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Rajmohan Banavi (rajmohan@mindbricks.com)                   *
*                     MindBricks Confidential Proprietary.                     *
*                            All Rights Reserved.                              *
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
#include "stun_txn_api.h"
#include "stuns_api.h"
#include "stuns_int.h"
#include "stuns_utils.h"




int32_t stuns_utils_send_error_resp(stuns_instance_t *instance, 
                        stuns_rx_stun_pkt_t *stun_pkt, uint32_t error_code, 
                        char *reason, handle *pah_attr, uint32_t num_attr)
{
    int32_t status;
    handle h_error_code, h_resp;

    status = stun_msg_create_resp_from_req(
                        stun_pkt->h_msg, STUN_ERROR_RESP, &h_resp);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the response message from request msg failed");
        return status;
    }

    /** now add error code attribute */
    status = stun_attr_create(STUN_ATTR_ERROR_CODE, &h_error_code);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the error-code attribute failed");
        goto ERROR_EXIT_PT1;
    }

    status = stun_attr_error_code_set_error_code(h_error_code, error_code);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code attribute value failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_attr_error_code_set_error_reason(
                                    h_error_code, reason, strlen(reason));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code reason value failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_msg_add_attribute(h_resp, h_error_code);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of error code attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Added error code attribute to response msg");

    /** add the given attributes */
    status = stun_msg_add_attributes(h_resp, pah_attr, num_attr);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of attributes to response message failed");
        goto ERROR_EXIT_PT2;
    }

    /** send the message to peer */
    status = instance->nwk_send_cb(h_resp, stun_pkt->src.host_type, 
                        stun_pkt->src.ip_addr, stun_pkt->src.port, 
                        stun_pkt->transport_param, NULL);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, "Sending of STUN message failed");
        goto ERROR_EXIT_PT1;
    }

    return STUN_OK;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_error_code);
ERROR_EXIT_PT1:
    stun_msg_destroy(h_resp);

    return status;

}



int32_t stuns_utils_send_success_resp(
            stuns_instance_t *instance, stuns_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    uint32_t i, count = 0;
    handle h_resp, h_resp_attrs[5];
    stun_addr_family_type_t addr_family = STUN_ADDR_FAMLY_INVALID;

    h_resp = NULL;
    count = 0;
    status = stun_msg_create_resp_from_req(
                    stun_pkt->h_msg, STUN_SUCCESS_RESP, &h_resp);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Creating the response message from "\
                "request msg failed");
        return status;
    }

    status = stun_attr_create(
                    STUN_ATTR_XOR_MAPPED_ADDR, &(h_resp_attrs[count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Creating the xor_mapped_addr attribute failed");
        goto ERROR_EXIT_PT;
    }
    count++;

    if (stun_pkt->src.host_type == STUN_INET_ADDR_IPV4) {
        addr_family = STUN_ADDR_FAMILY_IPV4;
    } else if (stun_pkt->src.host_type == STUN_INET_ADDR_IPV6) {
        addr_family = STUN_ADDR_FAMILY_IPV6;
    }

    status = stun_attr_xor_mapped_addr_set_address(
                                    h_resp_attrs[count-1], stun_pkt->src.ip_addr,
                                    strlen((char *)stun_pkt->src.ip_addr),
                                    addr_family);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Setting of the xor mapped addr to "\
                "xor_mapped_addr attribute failed");
        goto ERROR_EXIT_PT;
    }

    status = stun_attr_xor_mapped_addr_set_port(
                        h_resp_attrs[count-1], stun_pkt->src.port);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Setting of the xor mapped port to "\
                "xor_mapped_addr attribute failed");
        goto ERROR_EXIT_PT;
    }

    status = stun_attr_create(STUN_ATTR_SOFTWARE, &(h_resp_attrs[count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Creating the software attribute failed");
        goto ERROR_EXIT_PT;
    }
    count++;

    status = stun_attr_software_set_value(h_resp_attrs[count-1], 
                        instance->client_name, instance->client_name_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] setting the software value failed");
        goto ERROR_EXIT_PT;
    }

    /** Should we add fingerprint? */
    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(h_resp_attrs[count]));
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] Creating the fingerprint attribute failed");
        goto ERROR_EXIT_PT;
    }
    count++;

    /** add all the attributes */
    status = stun_msg_add_attributes(h_resp, h_resp_attrs, count);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[STUNS] setting the software value failed");
        goto ERROR_EXIT_PT;
    }
    count = 0;

    /** now send out the response */
    i = instance->nwk_send_cb(h_resp, stun_pkt->src.host_type, 
                        stun_pkt->src.ip_addr, stun_pkt->src.port, 
                        stun_pkt->transport_param, NULL);
    if (i <= 0)
    { 
        ICE_LOG(LOG_SEV_ERROR, "Sending of STUN message failed");
        status = STUN_TRANSPORT_FAIL;
        goto ERROR_EXIT_PT;
    }

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < count; i++)
        stun_attr_destroy(h_resp_attrs[i]);

    stun_msg_destroy(h_resp);

    return status;
}



int32_t stuns_utils_process_stun_binding_request(
                stuns_instance_t *instance, stuns_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    handle h_comp_reqd[5];
    uint32_t num = 5;

    /** section 7.3 - Receiving a STUN message - rfc 5389 */

    /** TODO-check if FINGERPRINT present, then it contains the correct value */

    /** no authentication mechanism */

    /** ignore the unknown comprehension-optional attributes */

    /** ignore the known but unexpected attributes */

    /** handle the unknown-comprehension required attributes - send 420 */
    num = 5;
    status = stun_msg_get_specified_attributes(stun_pkt->h_msg, 
                STUN_ATTR_UNKNOWN_COMP_REQUIRED, h_comp_reqd, &num);
    if ((status == STUN_OK) && (num > 0))
    {
        handle h_unknown;
        uint16_t i, attr_type;

        status = stun_attr_create(STUN_ATTR_UNKNOWN_ATTRIBUTES, &h_unknown);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Error while creating STUN_ATTR_UNKNOWN_ATTRIBUTES "\
                    "attribute");
            return status;
        }

        for (i = 0; i < num; i++)
        {
            status = stun_extended_attr_get_attr_type(
                                        h_comp_reqd[i], &attr_type);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, 
                        "Error while getting attribute type value from "\
                        "extended attribute");
                goto ERROR_EXIT;
            }

            status = stun_attr_unknown_attributes_add_attr_type(
                                                    h_unknown, attr_type);
            if(status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, 
                    "Unable to add unknown attribute type to unknown-attributes");
                goto ERROR_EXIT;
            }
        }

        /** ready to send a success response now */
        status = stuns_utils_send_error_resp(instance, stun_pkt, 
                        STUN_ERROR_UNKNOWN_ATTR, STUN_REJECT_RESPONSE_420, 
                        &h_unknown, 1);
        if (status != STUN_OK)
        {
            printf("Unable to send error response: [420]\n");
            return status;
        }
    }
    else if ((status != STUN_NOT_FOUND) && (status != STUN_OK))
    {
        /** TODO */
        printf ("Some critical error \n");
        return status;
    }

    printf("Now we should send out the response\n");
    status = stuns_utils_send_success_resp(instance, stun_pkt);
    if (status != STUN_OK)
    {
        printf("Error while sending success response\n");
    }

    return status;

ERROR_EXIT:
    return status;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
