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
        return false;

    retval = inet_pton(family, (const char *)host1, &addr1);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_INFO, 
            "[ICE UTILS] inet_pton failed, probably invalid address [%s]", 
            host1);
        return false;
    }

    retval = inet_pton(family, (const char *)host2, &addr2);
    if (retval != 1)
    {
        ICE_LOG(LOG_SEV_INFO, 
            "[ICE UTILS] inet_pton failed, probably invalid address [%s]",
            host2);
        return false;
    }
    
    retval = stun_memcmp(addr1, addr2, size);
    if (retval == 0)
    {
        ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE UTILS] Given IP addresses matched");
        return true;
    }

    ICE_LOG(LOG_SEV_DEBUG, 
            "[ICE UTILS] Given IP addresses differ");

    return false;
}



int32_t turns_utils_verify_info_from_alloc_request(
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
        *error_code = 401;
        return status;
    }
    else if (status != STUN_OK) return status;

    status = stun_attr_username_get_username_length(h_attr, &len);
    if (status != STUN_OK)
    {
        *error_code = 400;
        return status;
    }

    username = (u_char *) stun_calloc(1, len);
    if(username == NULL) return STUN_MEM_ERROR;

    status = stun_attr_username_get_username(h_attr, username, &len);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT1;
    }

    if (alloc->state == TSALLOC_CHALLENGED)
    {
        /**
         * at this time, we do not have any information on the username. so
         * just copy what the client has provided and pass on to the server app.
         */
        alloc->username = username;
        alloc->username_len = len;
        username = NULL;
    }
    else
    {
        /** TODO - need to verify against what is stored in the allocation */
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


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                    STUN_ATTR_REQUESTED_TRANSPORT, &h_attr, &num);
    if (status != STUN_OK)
    {
        resp_code = 400;
        goto MB_ERROR_EXIT2;
    }

    /** TODO - need to verify NONCE, MESSAGE INTEGRITY and FINGERPRINT */

    status = stun_attr_requested_transport_get_protocol(h_attr, &protocol);
    if (status != STUN_OK) goto MB_ERROR_EXIT2;

    /** RFC 5766 supports UDP only */
    if(protocol == STUN_TRANSPORT_UDP)
    {
        alloc->req_tport = ICE_TRANSPORT_UDP;
    }
    //else if (protocol == STUN_TRANSPORT_TCP)
    //    params->protocol = ICE_TRANSPORT_TCP;
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

    return status;

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

    /** notify the application for approval */
    alloc->instance->new_alloc_cb(NULL, params);

    return STUN_OK;
}



int32_t turns_utils_create_error_response(turns_allocation_t *ctxt, 
                            handle h_req, uint32_t error_code, handle *h_errmsg)
{
    int32_t status;
    handle h_error_code, h_resp, h_software;

    status = stun_msg_create_resp_from_req(h_req, STUN_ERROR_RESP, &h_resp);
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
                                    h_error_code, "Unauthorized", strlen("Unauthorized"));
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
            goto ERROR_EXIT_PT1;
        }

        status = stun_msg_utils_add_unknown_attributes(
                                                h_resp, h_unknown_attr, num);
    }
    else if (error_code == 401)
    {
        handle h_realm, h_nonce;

        status = stun_attr_create(STUN_ATTR_REALM, &h_realm);
        if (status != STUN_OK) return status;
        /** TODO: handle graceful exit */

        status = stun_attr_realm_set_realm(h_realm, 
                (uint8_t *)ctxt->instance->realm, ctxt->instance->realm_len);
        if (status != STUN_OK) return status;
        /** TODO: handle graceful exit */

        status = stun_msg_add_attribute(h_resp, h_realm);
        if (status != STUN_OK) return status;

        status = stun_attr_create(STUN_ATTR_NONCE, &h_nonce);
        if (status != STUN_OK) return status;
        /** TODO: handle graceful exit */

        status = stun_attr_nonce_set_nonce(h_nonce, 
                            ctxt->nonce, TURNS_SERVER_NONCE_LEN);
        if (status != STUN_OK) return status;
        /** TODO: handle graceful exit */

        status = stun_msg_add_attribute(h_resp, h_nonce);
        if (status != STUN_OK) return status;
    }

    status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_software);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "Creating the software attribute failed");
        goto ERROR_EXIT_PT1;
    }

    status = stun_attr_software_set_value(h_software, 
                            ctxt->instance->client_name, 
                            ctxt->instance->client_name_len);
    if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, "setting software attribute value failed");
        goto ERROR_EXIT_PT2;
    }

    status = stun_msg_add_attribute(h_resp, h_software);
    if (status != STUN_OK)
    { 
        ICE_LOG(LOG_SEV_ERROR, 
            "Adding of software attribute to response message failed");
        goto ERROR_EXIT_PT2;
    }

    *h_errmsg = h_resp;
    return STUN_OK;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_error_code);
ERROR_EXIT_PT1:
    stun_msg_destroy(h_resp);
    *h_errmsg = NULL;

    return status;
}



turns_allocation_t *turns_utils_create_allocation_context(
        turns_instance_t *instance, turns_rx_stun_pkt_t *stun_pkt)
{
    turns_allocation_t *new_ctxt;

    new_ctxt = (turns_allocation_t *) 
            stun_calloc (1, sizeof(turns_allocation_t));
    if (new_ctxt == NULL) return new_ctxt;

    new_ctxt->instance = instance;

    new_ctxt->protocol = stun_pkt->protocol;
    new_ctxt->transport_param = stun_pkt->transport_param;
    stun_memcpy(&new_ctxt->client_addr, 
                    &stun_pkt->src, sizeof(stun_inet_addr_t));

    /** Note : TODO
     * - Can we generate the nonce here for the allocation? so that every time
     *   an allocation is created, the nonce is automatically generated.
     * - in case we generate the nonce here, then we can also start the nonce
     *   stale timer here after above step for expiring the nonce. 
     */
    /** generate random nonce */
    turns_generate_nonce_value((char *)new_ctxt->nonce, TURNS_SERVER_NONCE_LEN);

    /** TODO - should we start the nonce stale timer here now? */

    /** Initialize to some default state? */
    // new_ctxt->state = 

    return new_ctxt;
}


#if 0

int32_t turn_utils_create_request_msg(turn_session_t *session, 
                                    stun_method_type_t method, handle *h_msg)
{
    int32_t status;
    handle h_req, h_vendor;

    status = stun_msg_create(STUN_REQUEST, method, &h_req);
    if (status != STUN_OK) return status;

    /** software attribute */
    if (session->instance->client_name)
    {
        status = stun_attr_create(STUN_ATTR_SOFTWARE, &h_vendor);
        if (status != STUN_OK) goto ERROR_EXIT_PT1;

        status = stun_attr_software_set_value(h_vendor, 
                                            session->instance->client_name, 
                                            session->instance->client_name_len);
        if (status != STUN_OK) goto ERROR_EXIT_PT2;

        status = stun_msg_add_attribute(h_req, h_vendor);
        if (status != STUN_OK) goto ERROR_EXIT_PT2;
    }

    *h_msg = h_req;
    return status;

ERROR_EXIT_PT2:
    stun_attr_destroy(h_vendor);

ERROR_EXIT_PT1:
    stun_msg_destroy(h_req);

    return status;
}



int32_t turn_utils_cache_auth_params(turn_session_t *session, handle h_msg)
{
    int32_t status;
    handle h_attr;
    uint32_t num, len;
    u_char *realm;

    /** realm */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_REALM, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_realm_get_realm_length(h_attr, &len);
    if (status != STUN_OK) return status;

    /** 
     * check if the realm attribute in the received response is 
     * the same as the realm that has been provisioned.
     */
    if (len != stun_strlen((char *)session->cfg.realm))
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] Length of realm in the received response is not "\
                "the same as the provisioned realm. Hence ignoring msg");
        return STUN_VALIDATON_FAIL;
    }
    
    realm = (u_char *) stun_calloc (1, len);
    if (realm == NULL) return STUN_MEM_ERROR;
   
    status = stun_attr_realm_get_realm(h_attr, realm, &len);
    if (status != STUN_OK)
    {
        stun_free(realm);
        return status;
    }

    if (stun_memcmp(session->cfg.realm, realm, len) != 0)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] realm in the received response is not the same as "\
                "the provisioned realm. Hence ignoring the received message");
        stun_free(realm);
        return STUN_VALIDATON_FAIL;
    }

    stun_free(realm);

    /** nonce */
    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_NONCE, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_nonce_get_nonce_length(h_attr, &len);
    if (status != STUN_OK) return status;

    if (len > session->nonce_len)
    {
        stun_free(session->nonce);

        session->nonce = (u_char *) stun_calloc (1, len);
        if (session->nonce == NULL) return STUN_MEM_ERROR;
    }
   
    session->nonce_len = len;

    status = stun_attr_nonce_get_nonce(h_attr, 
                            session->nonce, &(session->nonce_len));
    if (status != STUN_OK) return status;


    return STUN_OK;
}



int32_t turn_utils_create_alloc_req_msg_with_credential(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;

    status = turn_utils_create_request_msg(session, STUN_METHOD_ALLOCATE, &h_msg);
    if (status != STUN_OK) return status;
    
     
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    
    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
            session->cfg.realm, stun_strlen((char *)session->cfg.realm));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                                ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) return status;

    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



int32_t turn_utils_create_dealloc_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                            STUN_METHOD_REFRESH, &h_msg);
    if (status != STUN_OK) return status;


    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                                session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
            session->cfg.realm, stun_strlen((char *)session->cfg.realm));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                            ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_LIFETIME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_lifetime_set_duration(ah_attr[attr_count - 1], 0);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                            &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



int32_t turn_utils_extract_data_from_alloc_resp(
                                turn_session_t *session, handle h_msg)
{
    handle h_attr;
    int32_t status;
    uint32_t num, len;
    stun_addr_family_type_t addr_family;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_MAPPED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_mapped_addr_get_address(h_attr, 
                            &addr_family, session->mapped_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_mapped_addr_get_port(
                                    h_attr, &(session->mapped_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only? */
    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        session->mapped_addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        session->mapped_addr.host_type = STUN_INET_ADDR_IPV6;
    else
        session->mapped_addr.host_type = STUN_INET_ADDR_MAX;


    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_XOR_RELAYED_ADDR, &h_attr, &num);
    if (status != STUN_OK) return status;

    len = TURN_SVR_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_relayed_addr_get_address(h_attr, 
                            &addr_family, session->relay_addr.ip_addr, &len);
    if (status != STUN_OK) return status;

    status = stun_attr_xor_relayed_addr_get_port(
                                    h_attr, &(session->relay_addr.port));
    if (status != STUN_OK) return status;

    /** turn rfc supports IPv4 only */
    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        session->relay_addr.host_type = STUN_INET_ADDR_IPV4;
    else if (addr_family == STUN_ADDR_FAMILY_IPV6)
        session->relay_addr.host_type = STUN_INET_ADDR_IPV6;
    else
        session->relay_addr.host_type = STUN_INET_ADDR_MAX;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status != STUN_OK) return status;

    if (num > 0)
    {
        status = stun_attr_lifetime_get_duration(
                                    h_attr, &session->lifetime);
        if (status != STUN_OK) return status;
    }

    return status;
}



int32_t turn_utils_extract_data_from_refresh_resp(
                                turn_session_t *session, handle h_msg)
{
    handle h_attr;
    int32_t status;
    uint32_t num;

    num = 1;
    status = stun_msg_get_specified_attributes(h_msg, 
                                STUN_ATTR_LIFETIME, &h_attr, &num);
    if (status != STUN_OK) return status;

    status = stun_attr_lifetime_get_duration(
                                h_attr, &session->lifetime);
    return status;
}



int32_t turn_utils_create_refresh_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                            STUN_METHOD_REFRESH, &h_msg);
    if (status != STUN_OK) return status;

    
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
            session->cfg.realm, stun_strlen((char *)session->cfg.realm));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REQUESTED_TRANSPORT, 
                                            &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_requested_transport_set_protocol(
                                ah_attr[attr_count - 1], STUN_TRANSPORT_UDP);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_LIFETIME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    /** put in default refresh duration */
    status = stun_attr_lifetime_set_duration(
                        ah_attr[attr_count - 1], session->lifetime);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}




int32_t turn_session_utils_notify_state_change_event(turn_session_t *session)
{
    int32_t i, status = STUN_OK;
    turn_instance_t *instance = session->instance;

    session->instance->state_change_cb(
                    session->instance, session,  session->state);
   
    /** 
     * once the execution control goes back to the application via callback,
     * the application might destroy the session within the handler function.
     * Hence check for the validity of the session after returning from the
     * app callback handler. But the assumption is that the instance is intact.
     */
    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
        if (instance->ah_session[i] == session) break;

    if (i == TURN_MAX_CONCURRENT_SESSIONS) {
        ICE_LOG(LOG_SEV_ERROR, 
                "Invalid TURN session handle. Probably application destroyed "\
                "the session in the notification handler routine");
        status = STUN_TERMINATED;
    }

    return status;
}



int32_t turn_utils_start_alloc_refresh_timer(
                                turn_session_t *session, uint32_t duration)
{
    turn_timer_params_t *timer;

    if(session->alloc_refresh_timer_params == NULL)
    {
        session->alloc_refresh_timer_params = (turn_timer_params_t *) 
                                stun_calloc (1, sizeof(turn_timer_params_t));

        if (session->alloc_refresh_timer_params == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Memory allocation failed for TURN Allocation refresh timer");
            return STUN_MEM_ERROR;
        }
    }

    timer = session->alloc_refresh_timer_params;

    timer->h_instance = session->instance;
    timer->h_turn_session = session;
    timer->arg = NULL;
    timer->type = TURN_ALLOC_REFRESH_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of timer failed");
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURN session %p allocation "\
            "refresh timer for duration %d seconds timer %p ", 
            session, duration/1000, timer->timer_id);

    return STUN_OK;
}



int32_t turn_utils_stop_alloc_refresh_timer(turn_session_t *session)
{
    int32_t status = STUN_OK;

    if (session->alloc_refresh_timer_params == NULL) return status;
    if (session->alloc_refresh_timer_params->timer_id == NULL) return status;

    status = session->instance->stop_timer_cb(
                    session->alloc_refresh_timer_params->timer_id);
    if (status == STUN_OK) session->alloc_refresh_timer_params->timer_id = NULL;

    return status;
}



int32_t turn_utils_start_perm_refresh_timer(
                                turn_session_t *session, uint32_t duration)
{
    turn_timer_params_t *timer;

    if(session->perm_refresh_timer_params == NULL)
    {
        session->perm_refresh_timer_params = (turn_timer_params_t *) 
                                stun_calloc (1, sizeof(turn_timer_params_t));

        if (session->perm_refresh_timer_params == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Memory allocation failed for TURN Permission refresh timer");
            return STUN_MEM_ERROR;
        }
    }

    timer = session->perm_refresh_timer_params;

    timer->h_instance = session->instance;
    timer->h_turn_session = session;
    timer->arg = NULL;
    timer->type = TURN_PERM_REFRESH_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of timer failed");
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURN session %p permission "\
            "refresh timer for duration %d seconds timer %p ", 
            session, duration/1000, timer->timer_id);

    return STUN_OK;
}



int32_t turn_utils_stop_perm_refresh_timer(turn_session_t *session)
{
    int32_t status = STUN_OK;

    if (session->perm_refresh_timer_params == NULL) return status;
    if (session->perm_refresh_timer_params->timer_id == NULL) return status;

    status = session->instance->stop_timer_cb(
                    session->perm_refresh_timer_params->timer_id);
    if (status == STUN_OK) session->perm_refresh_timer_params->timer_id = NULL;

    return status;
}



int32_t turn_utils_start_keep_alive_timer(
                                turn_session_t *session, uint32_t duration)
{
    turn_timer_params_t *timer;

    if(session->keep_alive_timer_params == NULL)
    {
        session->keep_alive_timer_params = (turn_timer_params_t *) 
                                stun_calloc (1, sizeof(turn_timer_params_t));

        if (session->keep_alive_timer_params == NULL)
        {
            ICE_LOG(LOG_SEV_ERROR, 
                    "Memory allocation failed for TURN Keep Alive timer");
            return STUN_MEM_ERROR;
        }
    }

    timer = session->keep_alive_timer_params;

    timer->h_instance = session->instance;
    timer->h_turn_session = session;
    timer->arg = NULL;
    timer->type = TURN_KEEP_ALIVE_TIMER;

    timer->timer_id = session->instance->start_timer_cb(duration, timer);

    if(!timer->timer_id)
    {
        ICE_LOG(LOG_SEV_ERROR, "Starting of Keep Alive timer failed");
        return STUN_NO_RESOURCE;
    }

    ICE_LOG(LOG_SEV_INFO, "Started TURN session %p Keep Alive "\
            "timer for duration %d seconds timer %p ", 
            session, duration/1000, timer->timer_id);

    return STUN_OK;
}



int32_t turn_utils_stop_keep_alive_timer(turn_session_t *session)
{
    int32_t status = STUN_OK;

    if (session->keep_alive_timer_params == NULL) return status;
    if (session->keep_alive_timer_params->timer_id == NULL) return status;

    status = session->instance->stop_timer_cb(
                    session->keep_alive_timer_params->timer_id);
    if (status == STUN_OK) session->keep_alive_timer_params->timer_id = NULL;

    return status;
}



int32_t turn_utils_create_permission_req_msg(
                            turn_session_t *session, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    stun_addr_family_type_t addr_family;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;
    turn_permission_t *perm;


    status = turn_utils_create_request_msg(session, 
                                STUN_METHOD_CREATE_PERMISSION, &h_msg);
    if (status != STUN_OK) return status;

    /** Multiple xor XOR-PEER-ADDRESS attributes ca be added */
    for (i = 0; i < TURN_MAX_PERMISSIONS; i++)
    {
        if (session->aps_perms[i] == NULL) break; // continue?

        perm = session->aps_perms[i];

        status = stun_attr_create(STUN_ATTR_XOR_PEER_ADDR, 
                                                &(ah_attr[attr_count]));
        if (status != STUN_OK) goto ERROR_EXIT_PT;
        attr_count++;

        if (perm->peer_addr.host_type == STUN_INET_ADDR_IPV4)
            addr_family = STUN_ADDR_FAMILY_IPV4;
        else if (perm->peer_addr.host_type == STUN_INET_ADDR_IPV6)
            addr_family = STUN_ADDR_FAMILY_IPV6;
        else
            goto ERROR_EXIT_PT;


        status = stun_attr_xor_peer_addr_set_address(
                ah_attr[attr_count - 1], perm->peer_addr.ip_addr,
                strlen((char *)perm->peer_addr.ip_addr), addr_family);
        if (status != STUN_OK) goto ERROR_EXIT_PT;

        status = stun_attr_xor_peer_addr_set_port(
                        ah_attr[attr_count - 1], perm->peer_addr.port);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    if (attr_count == 0)
    {
        ICE_LOG(LOG_SEV_ERROR,
                "No Peer addresses set for installing permission");
        return STUN_INVALID_PARAMS;
    }
    
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
            session->cfg.realm, stun_strlen((char *)session->cfg.realm));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}



int32_t turn_utils_create_channel_bind_req_msg(turn_session_t *session, 
                                    turn_permission_t *perm, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    stun_addr_family_type_t addr_family;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_msg;


    status = turn_utils_create_request_msg(session, 
                                STUN_METHOD_CHANNEL_BIND, &h_msg);
    if (status != STUN_OK) return status;


    /** channel number */
    status = stun_attr_create(STUN_ATTR_CHANNEL_NUMBER, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_channel_number_set_channel(
                            ah_attr[attr_count], session->channel_num);
    if (status != STUN_OK) return status;
    session->channel_num += 1;


    /** xor peer address */
    status = stun_attr_create(STUN_ATTR_XOR_PEER_ADDR, 
                                            &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    if (perm->peer_addr.host_type == STUN_INET_ADDR_IPV4)
        addr_family = STUN_ADDR_FAMILY_IPV4;
    else if (perm->peer_addr.host_type == STUN_INET_ADDR_IPV6)
        addr_family = STUN_ADDR_FAMILY_IPV6;
    else
        goto ERROR_EXIT_PT;


    status = stun_attr_xor_peer_addr_set_address(
            ah_attr[attr_count - 1], perm->peer_addr.ip_addr,
            strlen((char *)perm->peer_addr.ip_addr), addr_family);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    status = stun_attr_xor_peer_addr_set_port(
                    ah_attr[attr_count - 1], perm->peer_addr.port);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    
    /** username */
    status = stun_attr_create(STUN_ATTR_USERNAME, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_username_set_username(ah_attr[attr_count - 1], 
                            session->cfg.username, 
                            strlen((char *)session->cfg.username));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    /** nonce */
    status = stun_attr_create(STUN_ATTR_NONCE, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_nonce_set_nonce(ah_attr[attr_count - 1], 
                            session->nonce, session->nonce_len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    /** realm */
    status = stun_attr_create(STUN_ATTR_REALM, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;

    status = stun_attr_realm_set_realm(ah_attr[attr_count - 1], 
            session->cfg.realm, stun_strlen((char *)session->cfg.realm));
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    status = stun_attr_create(STUN_ATTR_MESSAGE_INTEGRITY, 
                                                &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_attr_create(STUN_ATTR_FINGERPRINT, &(ah_attr[attr_count]));
    if (status != STUN_OK) goto ERROR_EXIT_PT;
    attr_count++;


    status = stun_msg_add_attributes(h_msg, ah_attr, attr_count);
    if (status != STUN_OK) goto ERROR_EXIT_PT;


    *h_newmsg = h_msg;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_msg);

    return status;
}




int32_t turn_utils_create_send_ind_msg(
        turn_session_t *session, turn_app_data_t *data, handle *h_newmsg)
{
    int32_t status, i, attr_count = 0;
    stun_addr_family_type_t addr_family;
    handle ah_attr[MAX_STUN_ATTRIBUTES] = {0}, h_ind;

    status = stun_msg_create(STUN_INDICATION, STUN_METHOD_SEND, &h_ind);
    if (status != STUN_OK) return status;

    if ((data) && (data->dest))
    {
        if (data->dest->host_type == STUN_INET_ADDR_IPV4)
            addr_family = STUN_ADDR_FAMILY_IPV4;
        else if (data->dest->host_type == STUN_INET_ADDR_IPV6)
            addr_family = STUN_ADDR_FAMILY_IPV6;
        else
            goto ERROR_EXIT_PT;

        status = stun_attr_create(STUN_ATTR_XOR_PEER_ADDR, 
                                                &(ah_attr[attr_count]));
        if (status != STUN_OK) goto ERROR_EXIT_PT;
        attr_count++;

        status = stun_attr_xor_peer_addr_set_address(
                ah_attr[attr_count - 1], data->dest->ip_addr,
                strlen((char *)data->dest->ip_addr), addr_family);
        if (status != STUN_OK) goto ERROR_EXIT_PT;

        status = stun_attr_xor_peer_addr_set_port(
                        ah_attr[attr_count - 1], data->dest->port);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    if (data && (data->data) && (data->len > 0))
    {
        status = stun_attr_create(STUN_ATTR_DATA, &(ah_attr[attr_count]));
        if (status != STUN_OK) goto ERROR_EXIT_PT;
        attr_count++;

        status = stun_attr_data_set_data(
                                ah_attr[attr_count - 1], data->data, data->len);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    /** TODO =
     * Add DONT-FRAGMENT attribute if configured
     */

    if (attr_count > 0)
    {
        status = stun_msg_add_attributes(h_ind, ah_attr, attr_count);
        if (status != STUN_OK) goto ERROR_EXIT_PT;
    }

    *h_newmsg = h_ind;

    return status;

ERROR_EXIT_PT:

    for (i = 0; i < attr_count; i++)
        stun_attr_destroy(ah_attr[i]);

    stun_msg_destroy(h_ind);

    return status;
}



int32_t turn_utils_process_data_indication(
                                turn_session_t *session, handle h_msg)
{
    int32_t status;
    uint32_t len;
    void *app_data;
    handle h_data_attr, h_xor_peer_addr;
    stun_inet_addr_t src;
    stun_addr_family_type_t addr_family;

    /**
     * TURN RFC 5766 sec 10.4 Receiving a Data Indication
     */

    len = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_XOR_PEER_ADDR, &h_xor_peer_addr, &len);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] XOR-PEER-ADDR attribute missing. Discarding the"\
                " received data indication message");
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] Extracting XOR-PEER-ADDR attribute from msg failed");
        return status;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "[TURN] XOR-PEER-ADDR attribute is present in the received msg");

    len = ICE_IP_ADDR_MAX_LEN;
    status = stun_attr_xor_peer_addr_get_address(
                        h_xor_peer_addr, &addr_family, src.ip_addr, &len);
    if (status != STUN_OK) return status;

    if (addr_family == STUN_ADDR_FAMILY_IPV4)
        src.host_type = STUN_INET_ADDR_IPV4;
    else
        src.host_type = STUN_INET_ADDR_IPV6;

    status = stun_attr_xor_peer_addr_get_port(h_xor_peer_addr, &src.port);
    if (status != STUN_OK) return status;

    ICE_LOG(LOG_SEV_CRITICAL,
            "TURN DATA IP Address %s:%d", src.ip_addr, src.port);

    /** TODO = 
     * This xor-peer-addr must be a valid one trusted by the 
     * application. Validate the received source IP address.
     */


    /** data attribute */
    len = 1;
    status = stun_msg_get_specified_attributes(
                    h_msg, STUN_ATTR_DATA, &h_data_attr, &len);
    if (status == STUN_NOT_FOUND)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] DATA attribute missing. Discarding the"\
                " received data indication message");
        return STUN_VALIDATON_FAIL;
    }
    else if (status != STUN_OK)
    {
        ICE_LOG(LOG_SEV_ERROR, 
                "[TURN] Extracting DATA attribute from msg failed");
        return status;
    }


    ICE_LOG(LOG_SEV_INFO, 
            "[TURN] DATA attribute is present in the received msg");

    status = stun_attr_data_get_data_length(h_data_attr, &len);
    if (status != STUN_OK) return STUN_INVALID_PARAMS;

    /** TODO = avoid calloc and memcpy in data path */
    app_data = (void *) stun_calloc (1, len);
    if (app_data == NULL) return STUN_MEM_ERROR;

    status = stun_attr_data_get_data(h_data_attr, app_data, len);
    if (status != STUN_OK) goto ERROR_EXIT_PT;

    /** pass on the data to the application */
    session->instance->rx_data_cb(session->instance, 
                    session, app_data, len, &src, session->transport_param);
    stun_free(app_data);

    return STUN_OK;

ERROR_EXIT_PT:
    stun_free(app_data);

    return status;
}



int32_t turn_table_validate_session_handle(handle h_inst, handle h_session)
{
    uint32_t i;
    turn_instance_t *instance = (turn_instance_t *) h_inst;

    for (i = 0; i < TURN_MAX_CONCURRENT_SESSIONS; i++)
    {
        if (h_session == instance->ah_session[i])
        {
            ICE_LOG (LOG_SEV_INFO, 
                    "[TURN] TURN session found while searching");
            return STUN_OK;
        }
    }

    ICE_LOG (LOG_SEV_ERROR, 
            "[TURN] TURN session handle NOT FOUND while searching");
    return STUN_NOT_FOUND;
}



void turn_utils_free_all_session_timers(turn_session_t *session)
{
    int32_t status;

    /** stop and free allocation refresh timer */
    status = turn_utils_stop_alloc_refresh_timer(session);
    if (status == STUN_OK)
        if (session->alloc_refresh_timer_params)
            stun_free(session->alloc_refresh_timer_params);

    session->alloc_refresh_timer_params = NULL;

    /** stop and free permission refresh timer */
    status = turn_utils_stop_perm_refresh_timer(session);
    if (status == STUN_OK)
        if (session->perm_refresh_timer_params)
            stun_free(session->perm_refresh_timer_params);

    session->perm_refresh_timer_params = NULL;

    /** stop and free keep-alive timer */
    status = turn_utils_stop_keep_alive_timer(session);
    if (status == STUN_OK)
        if (session->keep_alive_timer_params)
            stun_free(session->keep_alive_timer_params);

    session->keep_alive_timer_params = NULL;


    /** TODO free the channel binding refresh timer for each of the channels */

    return;
}



void turn_utils_delete_all_permissions(turn_session_t *session)
{
    int32_t i;
    turn_permission_t *perm;

    for (i = 0; i < TURN_MAX_PERMISSIONS; i++)
    {
        perm = session->aps_perms[i];
        if (perm == NULL) continue;

        /** TODO - stop and free the channel bind refresh timer */

        /** delete the channel bind transaction */
        stun_destroy_txn(session->instance->h_txn_inst, 
                                    perm->h_chnl_txn, false, false);

        /** free the memory for permission */
        stun_free(perm);
        session->aps_perms[i] = NULL;
    }

    return;
}



int32_t turn_utils_send_create_permission_req(turn_session_t *session)
{
    int32_t status = STUN_OK;
    handle h_txn, h_txn_inst;
    
    h_txn_inst = session->instance->h_txn_inst;

    /** delete an existing transaction, if any */
    stun_destroy_txn(h_txn_inst, session->h_perm_txn, false, false);
    session->h_perm_txn = session->h_perm_req = session->h_perm_resp = NULL;

    status = turn_utils_create_permission_req_msg(
                                session, &session->h_perm_req);
    if (status != STUN_OK) return status;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;


    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_perm_req);
    if (status != STUN_OK) return status;

    session->h_perm_txn = h_txn;

    return status;
}



int32_t turn_utils_send_channel_bind_request (
                            turn_session_t *session, turn_permission_t *perm)
{
    int32_t status;
    handle h_txn, h_txn_inst;
    
    h_txn_inst = session->instance->h_txn_inst;

    /** delete an existing transaction, if any */
    stun_destroy_txn(h_txn_inst, perm->h_chnl_txn, false, false);
    perm->h_chnl_txn = perm->h_chnl_req = perm->h_chnl_resp = NULL;

    status = turn_utils_create_channel_bind_req_msg(
                                session, perm, &session->h_perm_req);
    if (status != STUN_OK) return status;

    status = stun_create_txn(h_txn_inst,
                    STUN_CLIENT_TXN, STUN_UNRELIABLE_TRANSPORT, &h_txn);
    if (status != STUN_OK) return status;


    status = stun_txn_set_app_transport_param(h_txn_inst, h_txn, session);
    if (status != STUN_OK) return status;

    status = stun_txn_set_app_param(h_txn_inst, h_txn, (handle)session);
    if (status != STUN_OK) return status;

    status = stun_txn_send_stun_message(h_txn_inst, h_txn, session->h_perm_req);
    if (status != STUN_OK) return status;

    session->h_perm_txn = h_txn;

    return status;
}



int32_t turn_utils_validate_integrity_for_rcvd_msg(
                                    turn_session_t *session, handle h_rcvdmsg)
{
    stun_MD5_CTX ctx;
    int32_t len, status;
    u_char key[16];

    /** first generate the hmac key */
    stun_MD5_Init(&ctx);

    len = stun_strlen((char *)session->cfg.username);
    stun_MD5_Update(&ctx, session->cfg.username, len);
    stun_MD5_Update(&ctx, ":", 1);

    len = stun_strlen((char *)session->cfg.realm);
    stun_MD5_Update(&ctx, session->cfg.realm, len);
    stun_MD5_Update(&ctx, ":", 1);

    len = stun_strlen((char *)session->cfg.credential);
    stun_MD5_Update(&ctx, session->cfg.credential, len);

    stun_MD5_Final(key, &ctx);

    /** validate message integrity */
    len = 16;
    status = stun_msg_validate_message_integrity(h_rcvdmsg, key, len);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, "Validation of STUN response failed");
        return status;
    }

    return status;
}

#endif



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
