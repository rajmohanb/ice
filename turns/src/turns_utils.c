/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2013, MindBricks Technologies               *
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
#include "turns_api.h"
#include "turns_int.h"
#include "turns_utils.h"

#include <openssl/md5.h>



bool_t turns_generate_nonce_value(char *data, unsigned int len)
{
    /** TODO: 
     * need to revisit later, probably use 
     * /dev/urandom but will suffice for now
     */
    int i;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (i = 0; i < len; ++i)
    {
        *data = alphanum[rand() % (sizeof(alphanum) - 1)];
        data++;
    }

    //s[len] = 0;

#if 0
    static int fd = 0;

    if (fd == 0)
    {
        fd = open(DEV_RANDOM_FILE, O_RDONLY );

        if( fd == -1 ) {
            return false;
        }
    }

    read(fd, data, len);
#ifdef PLATFORM_DEBUG
    for ( i = 0; i < len; i++) {
        printf( "%x", data[i]);
    }
    printf("\n");
#endif
#endif
    
    return true;
}



bool_t turns_utils_host_compare (u_char *host1, 
                    u_char *host2, stun_inet_addr_type_t addr_type)
{
    int32_t retval, size, family;
    u_char addr1[TURNS_SIZEOF_IPV6_ADDR] = {0};
	u_char addr2[TURNS_SIZEOF_IPV6_ADDR] = {0};

    if (addr_type == STUN_INET_ADDR_IPV4)
    {
        family = AF_INET;
        size = TURNS_SIZEOF_IPV4_ADDR;
    }
    else if (addr_type == STUN_INET_ADDR_IPV6)
    {
        family = AF_INET6;
        size = TURNS_SIZEOF_IPV6_ADDR;
    }
    else
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Invalid IP address type for comparision - [%d]", addr_type);
        return false;
    }

    retval = inet_pton(family, (const char *)host1, &addr1);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "inet_pton failed, probably invalid address [%s]", host1);
        return false;
    }

    retval = inet_pton(family, (const char *)host2, &addr2);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "inet_pton failed, probably invalid address [%s]", host2);
        return false;
    }
    
    retval = stun_memcmp(addr1, addr2, size);
    if (retval == 0)
    {
        ICE_LOG(LOG_SEV_DEBUG, "Given IP addresses matched");
        return true;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Given IP addresses differ");

    return false;
}



int32_t turns_utils_pre_verify_info_from_alloc_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code)
{
    uint32_t num, protocol, resp_code, len;
    int32_t status;
    handle h_attr;
    u_char *realm, *nonce, *username;

    *error_code = 0;
    resp_code = 0;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_USERNAME, &h_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_DEBUG, "USERNAME attribute not found, sending 401");
        *error_code = 401;
        return status;
    }
    else if (status != STUN_OK) return status;

    status = stun_attr_username_get_username_length(h_attr, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "USERNAME attribute: Error retrieving length, sending 401");
        *error_code = 400;
        return status;
    }

    username = (u_char *) stun_calloc(1, len);
    if(username == NULL) return STUN_MEM_ERROR;

    status = stun_attr_username_get_username(h_attr, username, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "USERNAME attribute: Error retrieving username, sending 401");
        resp_code = 400;
        goto MB_ERROR_EXIT1;
    }

    /**
     * at this time, we do not have any information on the username. so
     * just copy what the client has provided and pass on to the server app.
     */
    alloc->username = username;
    alloc->username_len = len;
    username = NULL;
    ICE_LOG(LOG_SEV_DEBUG, "OK: So Username is %s", alloc->username);

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        resp_code = 401;
        goto MB_ERROR_EXIT1;
    }
    else if (status != STUN_OK) goto MB_ERROR_EXIT1;

    status = stun_attr_realm_get_realm_length(h_attr, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT1;
    }

    realm = (u_char *) stun_calloc(1, len);
    if(realm == NULL)
    {
        status = STUN_MEM_ERROR;
        goto MB_ERROR_EXIT1;
    }

    status = stun_attr_realm_get_realm(h_attr, realm, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    /** verify that the realm is valid */
    if ((len != alloc->instance->realm_len) || 
            (stun_strncmp((char *)realm, alloc->instance->realm, len) != 0))
    {
        /** realm mismatch */
        resp_code = 401;
        goto MB_ERROR_EXIT2;
    }


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                    STUN_ATTR_REQUESTED_TRANSPORT, &h_attr, &num);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_requested_transport_get_protocol(h_attr, &protocol);
    if (status != STUN_OK) goto MB_ERROR_EXIT2;

    /** RFC 5766 supports UDP only */
    if(protocol == STUN_TRANSPORT_UDP)
    {
        alloc->req_tport = ICE_TRANSPORT_UDP;
    }
    else if (protocol == STUN_TRANSPORT_TCP)
    {
        alloc->req_tport = ICE_TRANSPORT_TCP;
    }
    else
    {
        resp_code = 442;
        goto MB_ERROR_EXIT2; /** TODO - reject with 442 */
    }

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                    STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        alloc->lifetime = 0;
        status = STUN_OK;
    }
    else if (status == STUN_OK)
    {
        status = stun_attr_lifetime_get_duration(h_attr, &(alloc->lifetime));
        if (status != STUN_OK) goto MB_ERROR_EXIT2;
    }
    else
    {
        goto MB_ERROR_EXIT2;
    }

    /** 
     * need to verify NONCE, MESSAGE INTEGRITY and FINGERPRINT. The message 
     * integrity can only be verified after the server application provides
     * the hmac sha using the turn long term auth password. This will be done
     * in the post_verification of alloc request. However, the nonce and the
     * fingerprint can be checked here now.
     */
    num = 1;
    status = stun_msg_get_specified_attributes(
                        h_msg, STUN_ATTR_NONCE, &h_attr, &num);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_nonce_get_nonce_length(h_attr, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    nonce = (u_char *) stun_calloc(1, len);
    if(nonce == NULL)
    {
        status = STUN_MEM_ERROR;
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_nonce_get_nonce(h_attr, nonce, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "NONCE attribute: Error retrieving nonce, sending 401");
        resp_code = 400;
        goto MB_ERROR_EXIT3;
    }

    if ((len != TURNS_SERVER_NONCE_LEN) || 
            (memcmp(alloc->nonce, nonce, TURNS_SERVER_NONCE_LEN) != 0))
    {
        ICE_LOG(LOG_SEV_DEBUG, "Nonce do not match. Send 438 response");
        status = STUN_VALIDATON_FAIL;
        resp_code = 438;
        goto MB_ERROR_EXIT3;
    }

#ifdef TURNS_ENABLE_FINGERPRINT_VALIDATION
    /** fingerprint */
    status = stun_msg_validate_fingerprint(h_msg);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_INFO, "FingerPrint not present in request. Its OK?");
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, "FingerPrint did not match! sending 401");
        resp_code = 401;
        goto MB_ERROR_EXIT3;
    }
#endif /** TURNS_ENABLE_FINGERPRINT_VALIDATION */

    return status;

MB_ERROR_EXIT3:
    stun_free(nonce);
MB_ERROR_EXIT2:
    stun_free(realm);
MB_ERROR_EXIT1:
    if(username) stun_free(username);
    *error_code = resp_code;
    return status;
}



int32_t turns_utils_notify_new_alloc_request_to_app(turns_allocation_t *alloc)
{
    turns_new_allocation_params_t *params;

    params = (turns_new_allocation_params_t *) 
        stun_calloc(1, sizeof(turns_new_allocation_params_t));
    if (params == NULL) return STUN_MEM_ERROR;

    params->username = (u_char *) stun_calloc(1, alloc->username_len);
    if (params->username == NULL) return STUN_MEM_ERROR;

    stun_memcpy(params->username, alloc->username, alloc->username_len);
    params->username_len = alloc->username_len;

    params->realm = (u_char *) stun_calloc(1, alloc->instance->realm_len);
    if (params->realm == NULL) return STUN_MEM_ERROR;

    stun_memcpy(params->realm, 
            alloc->instance->realm, alloc->instance->realm_len);
    params->realm_len = alloc->instance->realm_len;

    params->lifetime = alloc->lifetime;
    params->protocol = alloc->req_tport;

    params->blob = (void *)alloc;

    /** notify the application for approval */
    alloc->instance->new_alloc_cb(alloc, params);

    return STUN_OK;
}



char *turns_utils_get_error_reason_phrase(uint32_t error_code)
{
    if (error_code == STUN_ERROR_TRY_ALTERNATE)
        return strdup(STUN_REJECT_RESPONSE_300);
    else if (error_code == STUN_ERROR_BAD_REQUEST)
        return strdup(STUN_REJECT_RESPONSE_400);
    else if (error_code == STUN_ERROR_UNAUTHORIZED)
        return strdup(STUN_REJECT_RESPONSE_401);
    else if (error_code == STUN_ERROR_FORBIDDEN)
        return strdup(STUN_REJECT_RESPONSE_403);
    else if (error_code == STUN_ERROR_UNKNOWN_ATTR)
        return strdup(STUN_REJECT_RESPONSE_420);
    else if (error_code == STUN_ERROR_ALLOC_MISMATCH)
        return strdup(STUN_REJECT_RESPONSE_437);
    else if (error_code == STUN_ERROR_STALE_NONCE)
        return strdup(STUN_REJECT_RESPONSE_438);
    else if (error_code == STUN_ERROR_WRONG_CREDS)
        return strdup(STUN_REJECT_RESPONSE_441);
    else if (error_code == STUN_ERROR_UNSUPPORTED_PROTO)
        return strdup(STUN_REJECT_RESPONSE_442);
    else if (error_code == STUN_ERROR_QUOTA_REACHED)
        return strdup(STUN_REJECT_RESPONSE_486);
    else if (error_code == STUN_ERROR_ROLE_CONFLICT)
        return strdup(STUN_REJECT_RESPONSE_487);
    else if (error_code == STUN_ERROR_SERVER_ERROR)
        return strdup(STUN_REJECT_RESPONSE_500);
    else if (error_code == STUN_ERROR_INSUF_CAPACITY)
        return strdup(STUN_REJECT_RESPONSE_508);
    else
        return NULL;
}



int32_t turns_utils_create_error_response(turns_allocation_t *ctxt, 
                            handle h_req, uint32_t error_code, handle *h_errmsg)
{
    int32_t i, status, count;
    handle h_resp, h_attrs[7];
    char *reason = NULL;

    count = 0;

    status = stun_msg_create_resp_from_req(h_req, STUN_ERROR_RESP, &h_resp);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the response message from request msg failed");
        return status;
    }

    /** add error code attribute */
    status = stun_attr_create(STUN_ATTR_ERROR_CODE, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the error-code attribute failed");
        goto MB_ERROR_EXIT1;
    }
    count++;

    status = stun_attr_error_code_set_error_code(h_attrs[count-1], error_code);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code attribute value failed");
        goto MB_ERROR_EXIT2;
    }

    reason = turns_utils_get_error_reason_phrase(error_code);
    /** TODO - what if this returns NULL */

    status = stun_attr_error_code_set_error_reason(
                            h_attrs[count-1], reason, strlen(reason));
    free(reason);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting error code reason value failed");
        goto MB_ERROR_EXIT2;
    }

    if (error_code == 420)
    {
        handle h_unknown_attr[5];
        uint32_t num = 5;

        status = stun_msg_get_specified_attributes(h_req, 
                        STUN_ATTR_UNKNOWN_COMP_REQUIRED, h_unknown_attr, &num);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                "Adding of error code attribute to response message failed");
            goto MB_ERROR_EXIT2;
        }

        status = stun_msg_utils_add_unknown_attributes(
                                                h_resp, h_unknown_attr, num);
        if (status != STUN_OK)
        {
            /** but we continue!!! */
            ICE_LOG(LOG_SEV_INFO, "Adding unknown attributes failed");
        }
    }
    else if ((error_code == 401) || (error_code == 438))
    {
        status = stun_attr_create(STUN_ATTR_REALM, &h_attrs[count]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_INFO, "Creating of realm attribute failed");
            goto MB_ERROR_EXIT2;
        }
        count++;

        status = stun_attr_realm_set_realm(h_attrs[count-1], 
                (uint8_t *)ctxt->instance->realm, ctxt->instance->realm_len);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_INFO, "Setting of realm attribute value failed");
            goto MB_ERROR_EXIT2;
        }

        status = stun_attr_create(STUN_ATTR_NONCE, &h_attrs[count]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_INFO, "Creating of nonce attribute failed");
            goto MB_ERROR_EXIT2;
        }
        count++;

        status = stun_attr_nonce_set_nonce(h_attrs[count-1], 
                            ctxt->nonce, TURNS_SERVER_NONCE_LEN);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_INFO, "Setting of nonce attribute value failed");
            goto MB_ERROR_EXIT2;
        }
    }

    status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the software attribute failed");
        goto MB_ERROR_EXIT2;
    }
    count++;

    status = stun_attr_software_set_value(h_attrs[count-1], 
                            ctxt->instance->client_name, 
                            ctxt->instance->client_name_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting software attribute value failed");
        goto MB_ERROR_EXIT2;
    }

    /** now add all the attributes */
    status = stun_msg_add_attributes(h_resp, h_attrs, count);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of array of attributes to response message failed");
        goto MB_ERROR_EXIT2;
    }

    *h_errmsg = h_resp;
    return STUN_OK;

MB_ERROR_EXIT2:
    for (i = 0; i < count; i++)
        stun_attr_destroy(h_attrs[i]);
MB_ERROR_EXIT1:
    stun_msg_destroy(h_resp);
    *h_errmsg = NULL;

    return status;
}



int32_t turns_utils_create_success_response(
                turns_allocation_t *ctxt, handle h_req, handle *h_msg)
{
    int32_t status, i, count = 0;
    handle h_resp, h_attrs[7] = {0};
    stun_addr_family_type_t family;
    stun_method_type_t method;

    status = stun_msg_create_resp_from_req(h_req, STUN_SUCCESS_RESP, &h_resp);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Creating the response message from request msg failed");
        return status;
    }

    stun_msg_get_method(h_resp, &method);

    if (method == STUN_METHOD_ALLOCATE)
    {
        /** xor relayed address attribute */
        status = stun_attr_create(STUN_ATTR_XOR_RELAYED_ADDR, &h_attrs[count]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                    "Creating the XOR relayed address attribute failed");
            goto ERROR_EXIT_PT1;
        }
        count++;

        if (ctxt->relay_addr.host_type == STUN_INET_ADDR_IPV4)
            family = STUN_ADDR_FAMILY_IPV4;
        else if (ctxt->relay_addr.host_type == STUN_INET_ADDR_IPV6)
            family = STUN_ADDR_FAMILY_IPV6;
        else
            family = STUN_ADDR_FAMLY_INVALID;

        status = stun_attr_xor_relayed_addr_set_address(h_attrs[count-1], 
                                ctxt->relay_addr.ip_addr, 
                                stun_strlen((char *)ctxt->relay_addr.ip_addr), 
                                family);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "setting xor relayed address attribute "\
                    "address value failed");
            goto ERROR_EXIT_PT2;
        }

        status = stun_attr_xor_relayed_addr_set_port(
                                h_attrs[count-1], ctxt->relay_addr.port);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "setting xor relayed address attribute port value failed");
            goto ERROR_EXIT_PT2;
        }

        /** xor mapped address attribute */
        status = stun_attr_create(STUN_ATTR_XOR_MAPPED_ADDR, &h_attrs[count]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "creating the xor mapped address attribute failed");
            goto ERROR_EXIT_PT2;
        }
        count++;

        if (ctxt->relay_addr.host_type == STUN_INET_ADDR_IPV4)
            family = STUN_ADDR_FAMILY_IPV4;
        else if (ctxt->relay_addr.host_type == STUN_INET_ADDR_IPV6)
            family = STUN_ADDR_FAMILY_IPV6;
        else
            family = STUN_ADDR_FAMLY_INVALID;

        status = stun_attr_xor_mapped_addr_set_address(h_attrs[count-1], 
                                ctxt->client_addr.ip_addr, 
                                stun_strlen((char *)ctxt->client_addr.ip_addr),
                                family);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR,
                   "setting xor mapped address attribute address value failed");
            goto ERROR_EXIT_PT2;
        }

        status = stun_attr_xor_mapped_addr_set_port(
                                h_attrs[count-1], ctxt->client_addr.port);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "setting xor mapped address attribute port value failed");
            goto ERROR_EXIT_PT2;
        }
    }

    if ((method == STUN_METHOD_ALLOCATE) || (method == STUN_METHOD_REFRESH))
    {
        /** lifetime attribute */
        status = stun_attr_create(STUN_ATTR_LIFETIME, &h_attrs[count]);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Creating the lifetime attribute failed");
            goto ERROR_EXIT_PT2;
        }
        count++;

        status = stun_attr_lifetime_set_duration(
                                h_attrs[count-1], ctxt->lifetime);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "setting lifetime attribute value failed");
            goto ERROR_EXIT_PT2;
        }
    }

    /** TODO - RESERVATION-TOKEN */

    /** TODO - software should be used only for allocate and refresh responses? */

    /** software */
    status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "creating the software attribute failed");
        goto ERROR_EXIT_PT2;
    }
    count++;

    status = stun_attr_software_set_value(h_attrs[count-1], 
            ctxt->instance->client_name, ctxt->instance->client_name_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting software attribute value failed");
        goto ERROR_EXIT_PT2;
    }

    /** message integrity */
    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "creating the message integrity attribute failed");
        goto ERROR_EXIT_PT2;
    }
    count++;


    /** fingerprint */
    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "creating the fingerprint attribute failed");
        goto ERROR_EXIT_PT2;
    }
    count++;


    /** add all the attributes */
    status = stun_msg_add_attributes(h_resp, h_attrs, count);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "Adding of attributes to the allocate request failed");
        goto ERROR_EXIT_PT2;
    }

    *h_msg = h_resp;
    return STUN_OK;

ERROR_EXIT_PT2:
    for (i = 0; i < count; i++)
        stun_attr_destroy(h_attrs[i]);
ERROR_EXIT_PT1:
    stun_msg_destroy(h_resp);
    *h_msg = NULL;

    return status;
}



int32_t turns_utils_init_allocation_context(
        turns_instance_t *instance, turns_allocation_t *context, 
        turns_rx_stun_pkt_t *stun_pkt)
{
    int32_t status;
    context->instance = instance;

    context->protocol = stun_pkt->protocol;
    context->transport_param = stun_pkt->transport_param;
    stun_memcpy(&context->client_addr, 
                    &stun_pkt->src, sizeof(stun_inet_addr_t));

    /** generate random nonce */
    turns_generate_nonce_value((char *)context->nonce, TURNS_SERVER_NONCE_LEN);

    /** start the nonce stale timer */
    status = turns_utils_start_nonce_stale_timer(context);

    /** Initialize to some default state? */
    context->state = TSALLOC_UNALLOCATED;

    /** 
     * copy the local interface details on which 
     * the allocation is being requested.
     */
    stun_memcpy(&context->relay_addr, 
                    &stun_pkt->local_intf, sizeof(stun_inet_addr_t));

    return status;
}



int32_t turns_utils_deinit_allocation_context(turns_allocation_t *alloc)
{
    int32_t i, status;
    turns_permission_t *perm;

    /** stop all the permission related timers */
    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if (perm->used == false) continue;

        status = turns_utils_stop_channel_binding_timer(alloc, perm);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Error! stopping the channel binding timer."\
                    " status [%d]", status);
        }

        status = turns_utils_stop_permission_timer(alloc, perm);
        if (status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Error! stopping the permission timer. "\
                    "status [%d]", status);
        }

        perm->used = false;
    }
 
    /** stop allocation nonce stale timer if running */
    status = turns_utils_stop_nonce_stale_timer(alloc);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! stopping the nonce stale timer. "\
                "status [%d]", status);
    }

    /** stop allocation refresh timer if running */
    status = turns_utils_stop_alloc_timer(alloc);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! stopping the allocation refresh timer. "\
                "status [%d]", status);
    }

    /** TODO: in the end, memset is safe? */
    stun_memset(alloc, 0, sizeof(turns_allocation_t));

    return status;
}



int32_t turns_utils_get_relayed_transport_address(turns_allocation_t *context)
{
    int32_t i, status, sock, sock_type;
    struct sockaddr addr;
    unsigned short sa_family;
    int ret;

    /**
     * how do we decide whether the client is requesting an IPv6
     * or an IPv4 relayed address? Currently using the local interface
     * address on which the request was received, to decide the same.
     */
    if (context->relay_addr.host_type == STUN_INET_ADDR_IPV4)
        sa_family = AF_INET;
    else if (context->relay_addr.host_type == STUN_INET_ADDR_IPV6)
        sa_family = AF_INET6;
    else
        return STUN_INT_ERROR;

    if (sa_family == AF_INET)
    {
        ret = inet_pton(AF_INET, (char *)context->relay_addr.ip_addr, 
                    &(((struct sockaddr_in *)&addr)->sin_addr));
        if (ret != 1) return STUN_INT_ERROR;
    }
    else
    {
        ret = inet_pton(AF_INET, (char *)context->relay_addr.ip_addr, 
                    &(((struct sockaddr_in6 *)&addr)->sin6_addr));
        if (ret != 1) return STUN_INT_ERROR;
    }

    if (context->req_tport == ICE_TRANSPORT_UDP)
        sock_type = SOCK_DGRAM;
    else if (context->req_tport == ICE_TRANSPORT_TCP)
        sock_type = SOCK_STREAM;
    else
        return STUN_INT_ERROR;

    sock = socket(sa_family, sock_type, 0);
    if (sock == -1) return STUN_NO_RESOURCE;

    addr.sa_family = sa_family;

    for (i = TURNS_PORT_RANGE_MIN; i <= TURNS_PORT_RANGE_MAX; i++)
    {
        if (sa_family == AF_INET)
            ((struct sockaddr_in *)&addr)->sin_port = htons(i);
        else
            ((struct sockaddr_in6 *)&addr)->sin6_port = htons(i);

        /** TODO - do we need to abstract the 'bind' to make it portable? */
        status = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
        if (status == -1)
        {
            ICE_LOG(LOG_SEV_DEBUG, "binding to port [%d] failed... "\
                   "perhaps port already being used? continuing the search", i);
            continue;
        }

        break;
    }

    if (i == TURNS_PORT_RANGE_MAX)
    {
        close(sock);
        return STUN_NO_RESOURCE;
    }

    context->relay_addr.port = i;
    context->relay_sock = sock;

    return STUN_OK;
}



int32_t turns_utils_setup_allocation(turns_allocation_t *context)
{
    int32_t status;

    /** RFC 5766 - 6.2.  Receiving an Allocate Request */
    status = turns_utils_get_relayed_transport_address(context);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ALERT, 
                "Unable to allocate TURN relayed address %d", status);
        return status;
    }

    return status;
}



int32_t turns_utils_start_alloc_timer(turns_allocation_t *alloc)
{
    turns_timer_params_t *timer = &alloc->alloc_timer_params;

    timer->h_instance = alloc->instance;
    timer->h_alloc = alloc;
    timer->arg = NULL;
    timer->type = TURNS_ALLOC_TIMER;

    timer->timer_id = 
        alloc->instance->start_timer_cb((alloc->lifetime * 1000), timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of allocation timer "\
                "for %d secs duration failed", alloc->lifetime);
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURNS allocation context %p "\
            "refresh timer for duration %d seconds timer id %p ", 
            alloc, alloc->lifetime, timer->timer_id);

    alloc->h_alloc_timer = timer->timer_id;

    return STUN_OK;
}



int32_t turns_utils_stop_alloc_timer(turns_allocation_t *alloc)
{
    int32_t status = STUN_OK;

    if (alloc->alloc_timer_params.timer_id == NULL) return status;

    status = alloc->instance->stop_timer_cb(
                    alloc->alloc_timer_params.timer_id);
    if (status == STUN_OK)
    {
        alloc->alloc_timer_params.timer_id = NULL;
        alloc->h_alloc_timer = NULL;
    }

    return status;
}



int32_t turns_utils_start_permission_timer(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    turns_timer_params_t *timer = &perm->perm_timer;

    timer->h_instance = alloc->instance;
    timer->h_alloc = alloc;
    timer->arg = perm;
    timer->type = TURNS_PERM_TIMER;

    timer->timer_id = alloc->instance->start_timer_cb(
                        (TURNS_PERM_REFRESH_DURATION * 1000), timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of channel binding timer "\
                "for %d secs duration failed", TURNS_PERM_REFRESH_DURATION);
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Started TURNS allocation context %p "\
            "channel bind timer for duration %d seconds timer id %p ", 
            alloc, TURNS_PERM_REFRESH_DURATION, timer->timer_id);

    perm->h_perm_timer = timer->timer_id;

    return STUN_OK;
}



int32_t turns_utils_stop_permission_timer(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    int32_t status = STUN_OK;

    if (perm->perm_timer.timer_id == NULL) return status;

    status = alloc->instance->stop_timer_cb(perm->perm_timer.timer_id);
    if (status == STUN_OK)
    {
        perm->perm_timer.timer_id = NULL;
        perm->h_perm_timer = NULL;
    }

    return status;
}



int32_t turns_utils_start_channel_binding_timer(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    turns_timer_params_t *timer = &perm->channel_timer;

    timer->h_instance = alloc->instance;
    timer->h_alloc = alloc;
    timer->arg = perm;
    timer->type = TURNS_CHNL_TIMER;

    timer->timer_id = alloc->instance->start_timer_cb(
                        (TURNS_CHANNEL_BINDING_DURATION * 1000), timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of channel binding timer "\
                "for %d secs duration failed", TURNS_CHANNEL_BINDING_DURATION);
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURNS allocation context %p "\
            "channel bind timer for duration %d seconds timer id %p ", 
            alloc, TURNS_CHANNEL_BINDING_DURATION, timer->timer_id);

    perm->h_channel_timer = timer->timer_id;

    return STUN_OK;
}



int32_t turns_utils_stop_channel_binding_timer(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    int32_t status = STUN_OK;

    if (perm->channel_timer.timer_id == NULL) return status;

    status = alloc->instance->stop_timer_cb(perm->channel_timer.timer_id);
    if (status == STUN_OK)
    {
        perm->channel_timer.timer_id = NULL;
        perm->h_channel_timer = NULL;
    }

    return status;
}



int32_t turns_utils_verify_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code)
{
    uint32_t num, resp_code, len, protocol;
    int32_t status;
    handle h_attr;
    u_char *realm, *nonce, *username;

    /** 
     * for any request subsequent to initial allocate, the parameters used for 
     * verification are username, realm, nonce and message integrity.
     */

    *error_code = 0;
    resp_code = 0;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_USERNAME, &h_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_INFO, "USERNAME attribute not found, sending 401");
        *error_code = 401;
        return status;
    }
    else if (status != STUN_OK) return status;

    status = stun_attr_username_get_username_length(h_attr, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_INFO, 
                "USERNAME attribute: Error retrieving length, sending 401");
        *error_code = 400;
        return status;
    }

    username = (u_char *) stun_calloc(1, len);
    if(username == NULL) return STUN_MEM_ERROR;

    status = stun_attr_username_get_username(h_attr, username, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "USERNAME attribute: Error retrieving username, sending 401");
        resp_code = 400;
        goto MB_ERROR_EXIT1;
    }

    /** verify against what is stored in the allocation */
    if ((len != alloc->username_len) || 
            (memcmp(alloc->username, username, len) != 0))
    {
        ICE_LOG(LOG_SEV_DEBUG, 
                "USERNAME mismatch. Rejecting the request message");
        status = STUN_VALIDATON_FAIL;
        resp_code = 401;
        goto MB_ERROR_EXIT1;
    }

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_attr, &num);
    if (status == STUN_NOT_FOUND)
    {
        resp_code = 401;
        goto MB_ERROR_EXIT1;
    }
    else if (status != STUN_OK) goto MB_ERROR_EXIT1;

    status = stun_attr_realm_get_realm_length(h_attr, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT1;
    }

    realm = (u_char *) stun_calloc(1, len);
    if(realm == NULL)
    {
        status = STUN_MEM_ERROR;
        goto MB_ERROR_EXIT1;
    }

    status = stun_attr_realm_get_realm(h_attr, realm, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    /** verify that the realm is valid */
    if ((len != alloc->instance->realm_len) || 
            (stun_strncmp((char *)realm, alloc->instance->realm, len) != 0))
    {
        /** realm mismatch */
        resp_code = 401;
        goto MB_ERROR_EXIT2;
    }


    /** nonce */
    num = 1;
    status = stun_msg_get_specified_attributes(
                        h_msg, STUN_ATTR_NONCE, &h_attr, &num);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_nonce_get_nonce_length(h_attr, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    nonce = (u_char *) stun_calloc(1, len);
    if(nonce == NULL)
    {
        status = STUN_MEM_ERROR;
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_nonce_get_nonce(h_attr, nonce, &len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_INFO, 
                "NONCE attribute: Error retrieving nonce, sending 401");
        resp_code = 400;
        goto MB_ERROR_EXIT3;
    }

    if ((len != TURNS_SERVER_NONCE_LEN) || 
            (memcmp(alloc->nonce, nonce, TURNS_SERVER_NONCE_LEN) != 0))
    {
        ICE_LOG(LOG_SEV_INFO, "Nonce do not match. Send 438 response");
        status = STUN_VALIDATON_FAIL;
        resp_code = 438;
        goto MB_ERROR_EXIT3;
    }


    /** message integrity */
    status = stun_msg_validate_message_integrity(
                    h_msg, alloc->hmac_key, TURNS_HMAC_KEY_LEN);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_INFO, "Message integrity did not match! sending 401");
        resp_code = 401;
        goto MB_ERROR_EXIT3;
    }

    /** 
     * make sure the requested protocol if present, is 
     * same as in the initial allocation request.
     */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                    STUN_ATTR_REQUESTED_TRANSPORT, &h_attr, &num);
    /** Its ok! ignore if not present or an error. lenient? */
    if (status == STUN_OK)
    {
        status = stun_attr_requested_transport_get_protocol(h_attr, &protocol);
        if (status == STUN_OK)
        {
            stun_transport_protocol_type_t type;

            if(protocol == STUN_TRANSPORT_UDP)
                type = ICE_TRANSPORT_UDP;
            else if (protocol == STUN_TRANSPORT_TCP)
                type = ICE_TRANSPORT_TCP;
            else
                type = ICE_TRANSPORT_INVALID;

            if (type != alloc->req_tport)
            {
                ICE_LOG(LOG_SEV_INFO, 
                        "The request transport type in the request does "\
                        "not match the one in the initial alloc request");
                resp_code = 401;
                goto MB_ERROR_EXIT3;
            }
        }
    }
    else if (status == STUN_NOT_FOUND)
    {
        status = STUN_OK;
    }
    else
    {
        resp_code = 400;
        goto MB_ERROR_EXIT3;
    }

#ifdef TURNS_ENABLE_FINGERPRINT_VALIDATION
    /** fingerprint */
    status = stun_msg_validate_fingerprint(h_msg);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_DEBUG, "FingerPrint not present in request. Its OK?");
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_DEBUG, "FingerPrint did not match! sending 401");
        resp_code = 401;
        goto MB_ERROR_EXIT3;
    }
#endif /** TURNS_ENABLE_FINGERPRINT_VALIDATION */

    return status;

MB_ERROR_EXIT3:
    stun_free(nonce);
MB_ERROR_EXIT2:
    stun_free(realm);
MB_ERROR_EXIT1:
    if(username) stun_free(username);
    *error_code = resp_code;
    return status;
}



int32_t turns_utils_start_nonce_stale_timer(turns_allocation_t *alloc)
{
    turns_timer_params_t *timer = &alloc->nonce_timer_params;

    timer->h_instance = alloc->instance;
    timer->h_alloc = alloc;
    timer->arg = NULL;
    timer->type = TURNS_NONCE_TIMER;

    timer->timer_id = alloc->instance->start_timer_cb(
                        (alloc->instance->nonce_timeout * 1000), timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of allocation stale nonce timer "\
                "for %d secs duration failed", alloc->instance->nonce_timeout);
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURNS allocation context %p "\
            "stale nonce timer for duration %d seconds timer id %p ", 
            alloc, alloc->instance->nonce_timeout, timer->timer_id);

    alloc->h_nonce_timer = timer->timer_id;

    return STUN_OK;
}



int32_t turns_utils_stop_nonce_stale_timer(turns_allocation_t *alloc)
{
    int32_t status = STUN_OK;

    if (alloc->nonce_timer_params.timer_id == NULL) return status;

    status = alloc->instance->stop_timer_cb(
                    alloc->nonce_timer_params.timer_id);
    if (status == STUN_OK)
    {
        alloc->nonce_timer_params.timer_id = NULL;
        alloc->h_nonce_timer = NULL;
    }

    return status;
}



int32_t turns_utils_verify_info_from_refresh_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code)
{
    int32_t status, num;
    handle h_attr;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_LIFETIME, &h_attr, (uint32_t *)&num);
    if (status == STUN_OK)
        status = stun_attr_lifetime_get_duration(h_attr, &(alloc->lifetime));

    return status;
}



int32_t turns_utils_search_permissions_for_channel_no(
                        turns_allocation_t *alloc, int32_t channel_no)
{
    int32_t i;
    turns_permission_t *perm;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if (perm->channel_num == channel_no) return STUN_OK;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Did not find any existing permission "\
            "with given channel number: %d", channel_no);

    return STUN_NOT_FOUND;
}



int32_t turns_utils_install_permission(turns_allocation_t *alloc, 
                                    uint16_t channel, stun_inet_addr_t *addr)
{
    int32_t i, status;
    turns_permission_t *perm;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if (perm->used == true) continue;

        stun_memcpy(&perm->peer_addr, addr, sizeof(stun_inet_addr_t));

        /** start permission refresh timer */
        status = turns_utils_start_permission_timer(alloc, perm);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Starting of permission refresh "\
                    "timer for %d secs duration failed");
            return STUN_NO_RESOURCE;
        }

        if (channel)
        {
            /** start channel binding timer */
            status = turns_utils_start_channel_binding_timer(alloc, perm);
            if(status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, "Starting of channel binding "\
                        "timer for %d secs duration failed");
                return STUN_NO_RESOURCE;
            }

            ICE_LOG(LOG_SEV_INFO, "Started TURNS allocation "\
                    "context %p channel binding timer", alloc);
        }

        perm->channel_num = channel;
        perm->used = true;
        perm->ingress_bytes = 0;
        perm->egress_bytes = 0;

        ICE_LOG(LOG_SEV_INFO, "Installed permission for %s:%d",
                            perm->peer_addr.ip_addr, perm->peer_addr.port);

        return STUN_OK;
    }

    /** reached the permission limit! */
    ICE_LOG(LOG_SEV_ALERT, "Reached the limit of the number "\
            "of permissions list for this allocation");

    return STUN_NO_RESOURCE;
}



int32_t turns_utils_uninstall_permission(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    int32_t status;

    if (perm->perm_timer.timer_id)
    {
        status = turns_utils_stop_permission_timer(alloc, perm);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Stopping of permission "\
                    "timer %p failed", perm->perm_timer.timer_id);
        }

        ICE_LOG(LOG_SEV_INFO, "Stopped TURNS permission timer for %p", alloc);
    }

    if (perm->channel_timer.timer_id)
    {
        status = turns_utils_stop_channel_binding_timer(alloc, perm);
        if(status != STUN_OK)
        {
            ICE_LOG(LOG_SEV_ERROR, "Stopping of permission channel binding "\
                    "timer %p failed", perm->channel_timer.timer_id);
        }

        ICE_LOG(LOG_SEV_INFO, "Stopped TURNS channel binding "\
                "timer for allocation %p", alloc);
    }

    stun_memset(&perm->peer_addr, 0, sizeof(stun_inet_addr_t));
    perm->channel_num = 0;
    perm->used = false;

    return STUN_OK;
}



int32_t turns_utils_refresh_permission(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    int32_t status;

    /** restart permission timer */
    status = turns_utils_stop_permission_timer(alloc, perm);
    if (status != STUN_OK)
    {
        /** should we raise an alarm and get out? */
        ICE_LOG(LOG_SEV_ALERT, "Unable to stop the permission timer");
    }

    status = turns_utils_start_permission_timer(alloc, perm);
    if(status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of permission timer "\
                "for %d secs duration failed");
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Started TURNS allocation "\
            "context %p channel binding timer", alloc);

    return status;
}



int32_t turns_utils_handle_create_permission_request(
                                turns_allocation_t *alloc, handle h_msg)
{
    int32_t i, status;
    handle h_resp, h_xor_peers[TURNS_MAX_PERMISSIONS];
    turns_permission_t *perm;
    uint32_t error_code, num, addr_len;
    stun_addr_family_type_t addr_family;
    stun_inet_addr_t addr;

    /** rfc 5766 - 9.2 Receiving a CreatePermission Request */

    /** check for XOR-PEER-ADDRESS attribute */

    /** TODO 
     * need to have an API that returns the number of specified attribute. 
     * If the number of attributes are more than what we support, then we 
     * can send some error response. In this case, if the number of xor 
     * peer address attributes are more than TURNS_MAX_PERMISSIONS, then 
     * we can send some 508 (insufficient capacity) e5ror response.
     */
    num = TURNS_MAX_PERMISSIONS;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_XOR_PEER_ADDR, h_xor_peers, &num);
    if (status == STUN_NOT_FOUND)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }
    else if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    for (i = 0; i < num; i++)
    {
        addr_len = ICE_IP_ADDR_MAX_LEN;
        status = stun_attr_xor_peer_addr_get_address(
                    h_xor_peers[i], &addr_family, addr.ip_addr, &addr_len);
        if (status != STUN_OK)
        {
            error_code = STUN_ERROR_BAD_REQUEST;
            goto MB_ERROR_EXIT1;
        }

        if (addr_family == STUN_ADDR_FAMILY_IPV4)
            addr.host_type = STUN_INET_ADDR_IPV4;
        else if (addr_family == STUN_ADDR_FAMILY_IPV6)
            addr.host_type = STUN_INET_ADDR_IPV6;
        else
        {
            error_code = STUN_ERROR_BAD_REQUEST;
            goto MB_ERROR_EXIT1;
        }

        status = stun_attr_xor_peer_addr_get_port(h_xor_peers[i], &addr.port);
        if (status != STUN_OK)
        {
            error_code = STUN_ERROR_BAD_REQUEST;
            goto MB_ERROR_EXIT1;
        }

        perm = turns_utils_search_for_permission(alloc, addr);
        if (!perm)
        {
            /** install new permission */
            status = turns_utils_install_permission(alloc, 0, &addr);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, "Error while installing the permission");
                error_code = STUN_ERROR_INSUF_CAPACITY;
                goto MB_ERROR_EXIT1;
            }
        }
        else
        {
            /** refresh the permission */
            status = turns_utils_refresh_permission(alloc, perm);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, "Refreshing the channel binding failed");
                error_code = STUN_ERROR_SERVER_ERROR;
                goto MB_ERROR_EXIT1;
            }
        }

        /** send out the success response */
        status = turns_utils_create_success_response(alloc, h_msg, &h_resp);
        if (status == STUN_OK)
        {
            alloc->h_resp = h_resp;

            /** send the success response */
            alloc->instance->nwk_stun_cb(h_resp, 
                    alloc->client_addr.host_type, 
                    alloc->client_addr.ip_addr, 
                    alloc->client_addr.port, 
                    alloc->transport_param, alloc->hmac_key);

            /** TODO: check if send succeeded */

            ICE_LOG(LOG_SEV_DEBUG, 
                    "Sent the create permission success response");

            ICE_LOG(LOG_SEV_DEBUG, "Installed/refreshed the permission");
        }
        else
        {
            ICE_LOG(LOG_SEV_ERROR, "Unable to create success response");
            error_code = STUN_ERROR_INSUF_CAPACITY;
            goto MB_ERROR_EXIT1;
        }
    }

    return status;

MB_ERROR_EXIT1:

    status = turns_utils_create_error_response(alloc, h_msg, error_code, &h_resp);

    if (status == STUN_OK)
    {
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, 
                alloc->hmac_key);

        /** TODO - check if sending succeeded */
        ICE_LOG(LOG_SEV_DEBUG, 
                "Sent the create permission error response: %d", error_code);
    }

    return status;
}



int32_t turns_utils_handle_channel_bind_request(
                                turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    handle h_channel, h_xor_peer, h_resp;
    stun_inet_addr_t addr;
    turns_permission_t *perm;
    uint32_t error_code, num, addr_len;
    stun_addr_family_type_t addr_family;
    uint16_t channel_no;

    /** rfc 5766 - 11.2 Receiving a ChannelBind Request */

    /** check for CHANNEL-NUMBER attribute */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_CHANNEL_NUMBER, &h_channel, &num);
    if (status == STUN_NOT_FOUND)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }
    else if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    status = stun_attr_channel_number_get_channel(h_channel, &channel_no);
    if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    /** validate the channel number range */
    if ((channel_no < TURNS_CHANNEL_NUMBER_MIN) || 
            (channel_no > TURNS_CHANNEL_NUMBER_MAX))
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    /** check for XOR-PEER-ADDRESS attribute */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                            STUN_ATTR_XOR_PEER_ADDR, &h_xor_peer, &num);
    if (status == STUN_NOT_FOUND)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }
    else if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    addr_len = ICE_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_peer_addr_get_address(
                        h_xor_peer, &addr_family, addr.ip_addr, &addr_len);
    if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        addr.host_type = STUN_INET_ADDR_IPV6;
    else
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    status = stun_attr_xor_peer_addr_get_port(h_xor_peer, &addr.port);
    if (status != STUN_OK)
    {
        error_code = STUN_ERROR_BAD_REQUEST;
        goto MB_ERROR_EXIT1;
    }

    /** check if the permission is already installed? */
    perm = turns_utils_search_for_permission(alloc, addr);
    if (!perm)
    {
        /** install a new permission with the channel binding */

        /** 
         * make sure the channel number is not currently 
         * bound to a different transport address.
         */
        status = 
            turns_utils_search_permissions_for_channel_no(alloc, channel_no);
        if (status != STUN_NOT_FOUND)
        {
            error_code = STUN_ERROR_BAD_REQUEST;
            goto MB_ERROR_EXIT1;
        }

        status = turns_utils_install_permission(alloc, channel_no, &addr);
        if (status == STUN_OK)
        {
            status = turns_utils_create_success_response(alloc, h_msg, &h_resp);
            if (status == STUN_OK)
            {
                alloc->h_resp = h_resp;

                /** send the success response */
                alloc->instance->nwk_stun_cb(h_resp, 
                        alloc->client_addr.host_type, 
                        alloc->client_addr.ip_addr, 
                        alloc->client_addr.port, 
                        alloc->transport_param, alloc->hmac_key);

                /** TODO: check if send succeeded */

                ICE_LOG(LOG_SEV_DEBUG, "Sent the channel bind success response");

                ICE_LOG(LOG_SEV_DEBUG, 
                        "Installed new permission and the channel binding");
            }
            else
            {
                ICE_LOG(LOG_SEV_ERROR, "Unable to create success response");
                error_code = STUN_ERROR_INSUF_CAPACITY;
                goto MB_ERROR_EXIT1;
            }
        }
        else
        {
            ICE_LOG(LOG_SEV_ERROR, "Error while installing the permission");
            error_code = STUN_ERROR_INSUF_CAPACITY;
            goto MB_ERROR_EXIT1;
        }
    }
    else
    {
        /** 
         * prior permission exists, refresh the permission. Also install or 
         * refresh the channel binding since this is a channel bind request.
         */

        /** 
         * make sure the transport address is not currently 
         * bound to a different channel number.
         */
        if ((perm->channel_num != 0) && (perm->channel_num != channel_no))
        {
            ICE_LOG(LOG_SEV_ERROR, "Error! Binding a new channel number [%d] "\
                    "to an already existing permission with channel "\
                    "number [%d]", channel_no, perm->channel_num);
            error_code = STUN_ERROR_BAD_REQUEST;
            goto MB_ERROR_EXIT1;
        }

        if ((perm->channel_num == 0) && (perm->h_channel_timer == NULL))
        {
            /** installing channel binding to the permission */
            status = 
                turns_utils_install_channel_binding(alloc, perm, channel_no);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, 
                        "Error! Installing a new channel binding failed");
                error_code = STUN_ERROR_SERVER_ERROR;
                goto MB_ERROR_EXIT1;
            }
        }
        else
        {
            /** refreshing the channel binding */
            status = turns_utils_refresh_channel_binding(alloc, perm);
            if (status != STUN_OK)
            {
                ICE_LOG(LOG_SEV_ERROR, "Refreshing the channel binding failed");
                error_code = STUN_ERROR_SERVER_ERROR;
                goto MB_ERROR_EXIT1;
            }
        }

        /** send out the success response */
        status = turns_utils_create_success_response(alloc, h_msg, &h_resp);
        if (status == STUN_OK)
        {
            alloc->h_resp = h_resp;

            /** send the success response */
            alloc->instance->nwk_stun_cb(h_resp, 
                    alloc->client_addr.host_type, 
                    alloc->client_addr.ip_addr, 
                    alloc->client_addr.port, 
                    alloc->transport_param, alloc->hmac_key);

            /** TODO: check if send succeeded */

            ICE_LOG(LOG_SEV_DEBUG, "Sent the channel bind success response");

            ICE_LOG(LOG_SEV_DEBUG, "Installed/refreshed the channel binding");
        }
        else
        {
            ICE_LOG(LOG_SEV_ERROR, "Error! Unable to create success response");
            error_code = STUN_ERROR_INSUF_CAPACITY;
            goto MB_ERROR_EXIT1;
        }
    }

    return status;

MB_ERROR_EXIT1:

    status = turns_utils_create_error_response(alloc, h_msg, error_code, &h_resp);

    if (status == STUN_OK)
    {
        alloc->instance->nwk_stun_cb(h_resp, 
                alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                alloc->client_addr.port, alloc->transport_param, 
                alloc->hmac_key);

        /** TODO - check if sending succeeded */
        ICE_LOG(LOG_SEV_DEBUG, 
                "Sent the channel bind error response: %d", error_code);
    }

    return status;
}



turns_permission_t *turns_utils_validate_allocation_channel_binding(
                                        turns_allocation_t *alloc, handle arg)
{
    int32_t i;
    turns_permission_t *perm;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if ((handle)perm != arg) continue;

        /** permission might have been de-allocated? */
        if (perm->used == false) break;

        /** permission might exist, but channel binding might not */
        if (!perm->channel_num) break;

        /** found the target! */
        return perm;
    }

    return NULL;
}



turns_permission_t *turns_utils_validate_permission_handle(
                                        turns_allocation_t *alloc, handle arg)
{
    int32_t i;
    turns_permission_t *perm;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if ((handle)perm != arg) continue;

        /** permission might have been de-allocated? */
        if (perm->used == false) break;

        /** found the target! */
        return perm;
    }

    return NULL;
}



turns_permission_t *turns_utils_search_for_permission(
                        turns_allocation_t *alloc, stun_inet_addr_t addr)
{
    int32_t i;
    turns_permission_t *perm = NULL;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if (perm->used == false) continue;

        /**
         * should we compare the port when checking if a permission has been 
         * installed? As per RFC 5766, "sec 9.2 - Receiving a CreatePermission 
         * Request", 'The port portion of each attribute is ignored and may 
         * be any arbitrary value.' Hence port comparision is not done!
         */
        if ((perm->peer_addr.host_type == addr.host_type) && 
            /* (perm->peer_addr.port == addr.port) && */
            (turns_utils_host_compare(perm->peer_addr.ip_addr, 
                                      addr.ip_addr, addr.host_type) == true))
        {
            return perm;
        }
    }

    ICE_LOG(LOG_SEV_DEBUG, "Permission NOT found");
    return NULL;
}



int32_t turns_utils_install_channel_binding(
        turns_allocation_t *alloc, turns_permission_t *perm, uint16_t channel)
{
    int32_t status;

    /** when channel binding is installed, the permission is refreshed */
    status = turns_utils_stop_permission_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! stopping the permission timer failed "\
                "when installing a channel binding. status [%d]", status);

        return status;
    }

    status = turns_utils_start_permission_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! starting the permission timer when "\
                "installing a channel binding. status [%d]", status);

        return status;
    }

    /** start the channel binding timer */
    status = turns_utils_start_channel_binding_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! starting the channel binding timer."\
               " status [%d]", status);

        return status;
    }

    perm->channel_num = channel;

    return status;
}



int32_t turns_utils_refresh_channel_binding(
                turns_allocation_t *alloc, turns_permission_t *perm)
{
    int32_t status;

    /** stop the channel binding timer */
    status = turns_utils_stop_channel_binding_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! stopping the channel binding timer. "\
                "status [%d]. However, continuing with the channel refresh", 
                status);
    }

    /** start the channel binding timer */
    status = turns_utils_start_channel_binding_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! starting the channel binding timer."\
               " status [%d]", status);
        return status;
    }

    /** when channel binding is refreshed, the permission also gets refreshed */
    status = turns_utils_stop_permission_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! stopping the permission timer. "\
                "status [%d]. However, continuing with the permission refresh",
                status);
    }

    /** start the channel binding timer */
    status = turns_utils_start_permission_timer(alloc, perm);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Error! starting the permission timer when "\
                "refreshing channel binding. status [%d]", status);

        return status;
    }

    return status;
}



int32_t turns_utils_forward_send_data(turns_allocation_t *alloc, handle h_msg)
{
    int32_t status;
    stun_inet_addr_t addr;
    handle h_peer, h_data;
    uint32_t addr_len, num, data_len;
    stun_addr_family_type_t addr_family;
    turns_permission_t *perm = NULL;
    u_char *data;

    /** get the peer address */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                        STUN_ATTR_XOR_PEER_ADDR, &h_peer, &num);
    if (status != STUN_OK)
    {
        goto MB_ERROR_EXIT;
    }

    addr_len = ICE_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_peer_addr_get_address(
                    h_peer, &addr_family, addr.ip_addr, &addr_len);
    if (status != STUN_OK)
    {
        goto MB_ERROR_EXIT;
    }

    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        addr.host_type = STUN_INET_ADDR_IPV6;
    else
    {
        goto MB_ERROR_EXIT;
    }

    status = stun_attr_xor_peer_addr_get_port(h_peer, &addr.port);
    if (status != STUN_OK)
    {
        goto MB_ERROR_EXIT;
    }

    /** check if the peer address has an associated permission installed */
    perm = turns_utils_search_for_permission(alloc, addr);
    if (!perm)
    {
        ICE_LOG(LOG_SEV_NOTICE, "Permission has not been installed for the "\
                "peer address present in the send indication message. "\
                "Hence dropping the message");
        goto MB_ERROR_EXIT;
    }

    /** if yes, then extract the data */
    num = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_DATA, &h_data, &num);
    if (status != STUN_OK)
    {
        goto MB_ERROR_EXIT;
    }

    status = stun_attr_data_get_data_length(h_data, &data_len);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    data = (u_char *) stun_calloc(1, data_len);
    if (data == NULL)
    {
        status = STUN_MEM_ERROR;
        goto MB_ERROR_EXIT;
    }

    status = stun_attr_data_get_data(h_data, data, data_len);
    if (status != STUN_OK) goto MB_ERROR_EXIT;

    /** TODO - handling of DONT-FRAGMENT attribute */

    /** send to peer using relayed address */
    num = alloc->instance->nwk_data_cb(data, data_len, 
            perm->peer_addr.host_type, perm->peer_addr.ip_addr, 
            perm->peer_addr.port, (handle)alloc->relay_sock, NULL);
    if (num <= 0)
    {
        ICE_LOG(LOG_SEV_ERROR, "Sending of UDP data to %s:%d failed", 
                                perm->peer_addr.ip_addr, perm->peer_addr.port);
        status = STUN_TRANSPORT_FAIL;
        goto MB_ERROR_EXIT;
    }

    ICE_LOG(LOG_SEV_DEBUG, "Sent UDP data of length %d to %s:%d", 
                num, perm->peer_addr.ip_addr, perm->peer_addr.port);

    perm->egress_bytes += num;

    printf("EGRESS BYTES: %d bytes\n", perm->egress_bytes);

    return status;

MB_ERROR_EXIT:

    ICE_LOG(LOG_SEV_ERROR, 
            "Error while processing SEND indication message, hence dropping");

    return status;
}



int32_t turns_utils_forward_channel_data(
                    turns_allocation_t *alloc, turns_rx_channel_data_t *data)
{
    int32_t status = STUN_OK;
    uint16_t i, channel;
    turns_permission_t *perm;
    uint32_t bytes = 0;

    /** get the channel number */
    stun_memcpy(&channel, data->data, sizeof(uint16_t));
    channel = ntohs(channel);

    /** check if the allocation has a peer bound to this channel */
    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if ((perm->channel_num == channel) && (perm->used == true)) break;
    }

    if (i == TURNS_MAX_PERMISSIONS)
    {
        ICE_LOG(LOG_SEV_NOTICE, "Error! Could not find any permission/peer "\
                "address associated with the channel number %d in the channel "\
                "data message. Hence dropping the message", channel);

        return STUN_INVALID_PARAMS;
    }

    /** if yes, then send out the data to the peer using relayed address */
    stun_memcpy(&i, (data->data+2), sizeof(uint16_t));
    i = ntohs(i);

    /** TODO : in case of TCP/TLS, padding needs to be done for the app data */

    bytes = alloc->instance->nwk_data_cb((data->data+4), i, 
            perm->peer_addr.host_type, perm->peer_addr.ip_addr, 
            perm->peer_addr.port, (handle)alloc->relay_sock, NULL);

    if (bytes <= 0)
    {
        ICE_LOG(LOG_SEV_ERROR, "Sending of UDP data to %s:%d failed", 
                                perm->peer_addr.ip_addr, perm->peer_addr.port);
        status = STUN_TRANSPORT_FAIL;
    }
    else
    {
        perm->egress_bytes += bytes;
        printf("EGRESS BYTES: %d bytes\n", perm->egress_bytes);
    }

    /** TODO : check if send really succeeded check return value */

    return status;
}



int32_t turns_utils_forward_udp_data_using_channeldata_msg(
                        turns_allocation_t *alloc, turns_permission_t *perm, 
                        turns_rx_channel_data_t *data)
{
    int32_t bytes, status = STUN_OK;
    char buf[1500] = {0};
    uint16_t channel, len;

    /** copy the channel number */
    channel = htons(perm->channel_num);
    stun_memcpy(buf, &channel, sizeof(uint16_t));

    /** set the length of payload */
    len = htons(data->data_len);
    stun_memcpy(buf+2, &len, sizeof(uint16_t));

    /** copy the data */
    stun_memcpy(buf+4, data->data, data->data_len);

#if 0
    /** padding - not strictly required for udp but mandated for tcp */
    //if (data->data % 4)
    //{
    //    stun_memcpy(buf + 4 + data->data_len, 0, (data->data % 4));
    //}
#endif

    /** send to the client */
    bytes = alloc->instance->nwk_data_cb((uint8_t *)buf, (data->data_len + 4), 
            alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
            alloc->client_addr.port, alloc->transport_param, NULL);

    if (bytes <= 0)
        status = STUN_TRANSPORT_FAIL;
    else
        perm->ingress_bytes += data->data_len;

    printf("INGRESS BYTES: %d bytes\n", perm->ingress_bytes);

    return status;
}



int32_t turns_utils_forward_udp_data_using_data_ind(
                        turns_allocation_t *alloc, turns_permission_t *perm, 
                        turns_rx_channel_data_t *data)
{
    int32_t i, status, count;
    handle h_ind, h_attrs[2];
    stun_addr_family_type_t addr_type;

    count = 0;

    status = stun_msg_create(STUN_INDICATION, STUN_METHOD_DATA, &h_ind);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating DATA indication  message msg failed");
        return status;
    }

    /** add xor peer address attribute */
    status = stun_attr_create(STUN_ATTR_XOR_PEER_ADDR, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "Creating the XOR Peer address attribute failed");
        goto MB_ERROR_EXIT1;
    }
    count++;

    if (data->src.host_type == STUN_INET_ADDR_IPV4)
        addr_type = STUN_ADDR_FAMILY_IPV4;
    else
        addr_type = STUN_ADDR_FAMILY_IPV6;
    status = stun_attr_xor_peer_addr_set_address(
                                    h_attrs[count-1], data->src.ip_addr, 
                                    ICE_IP_ADDR_MAX_LEN, addr_type);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Setting XOR peer address failed");
        goto MB_ERROR_EXIT2;
    }

    status = stun_attr_xor_peer_addr_set_port(h_attrs[count-1], data->src.port);
    if (status != STUN_OK) goto MB_ERROR_EXIT2;

    /** add data attribute */
    status = stun_attr_create(STUN_ATTR_DATA, &h_attrs[count]);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating DATA attribute failed %d", status);
        goto MB_ERROR_EXIT2;
    }
    count++;

    status = stun_attr_data_set_data(
            h_attrs[count-1], data->data, data->data_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting data to DATA attribute failed");
        goto MB_ERROR_EXIT2;
    }

    /** now add all the attributes */
    status = stun_msg_add_attributes(h_ind, h_attrs, count);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of array of attributes to data indication message failed");
        goto MB_ERROR_EXIT2;
    }

    /** send the message to the client */
    i = alloc->instance->nwk_stun_cb(h_ind, 
                    alloc->client_addr.host_type, alloc->client_addr.ip_addr, 
                    alloc->client_addr.port, alloc->transport_param, NULL);

    if (i <= 0)
    {
        status = STUN_TRANSPORT_FAIL;
        goto MB_ERROR_EXIT1;
    }

    perm->ingress_bytes += data->data_len;

    printf("INGRESS BYTES: %d bytes\n", perm->ingress_bytes);

    ICE_LOG(LOG_SEV_DEBUG, 
            "Forwarded UDP data using DATA IND to the client at %s:%d", 
            alloc->client_addr.ip_addr, alloc->client_addr.port);

    return status;

MB_ERROR_EXIT2:
    for (i = 0; i < count; i++)
        stun_attr_destroy(h_attrs[i]);
MB_ERROR_EXIT1:
    stun_msg_destroy(h_ind);
    return status;
}


int32_t turns_utils_post_verify_info_from_alloc_request(
                            turns_allocation_t *alloc, uint32_t *error_code)
{
    int32_t status;

    /** message integrity */
    status = stun_msg_validate_message_integrity(
                    alloc->h_req, alloc->hmac_key, TURNS_HMAC_KEY_LEN);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Message integrity did not match! sending 401");
        *error_code = 401;
    }

    return status;
}
 

int32_t turns_utils_calculate_allocation_relayed_data(
                        turns_allocation_t *alloc, uint64_t *ingress_data, 
                        uint64_t *egress_data)
{
    turns_permission_t *perm = NULL;
    uint64_t ingress = 0, egress = 0;
    uint16_t i;

    for (i = 0; i < TURNS_MAX_PERMISSIONS; i++)
    {
        perm = &alloc->aps_perms[i];
        if (perm->used == false) continue;

        ingress += perm->ingress_bytes;
        egress += perm->egress_bytes;
    }

    *ingress_data = ingress;
    *egress_data = egress;

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
