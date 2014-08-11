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

#ifndef TURNS_UTILS__H
#define TURNS_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



#define TURNS_SIZEOF_IPV6_ADDR    16      /** sizeof(struct in_addr) */

#define TURNS_SIZEOF_IPV4_ADDR    4       /** sizeof(struct in6_addr) */



bool_t turns_generate_nonce_value(char *data, unsigned int len);


bool_t turns_utils_host_compare (u_char *host1, 
                    u_char *host2, stun_inet_addr_type_t addr_type);


int32_t turns_utils_pre_verify_info_from_alloc_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code);

int32_t turns_utils_post_verify_info_from_alloc_request(
                        turns_allocation_t *alloc, uint32_t *error_code);

int32_t turns_utils_notify_new_alloc_request_to_app(turns_allocation_t *alloc);


int32_t turns_utils_create_success_response(
                turns_allocation_t *ctxt, handle h_req, handle *h_msg);


int32_t turns_utils_create_error_response(turns_allocation_t *ctxt, 
                    handle h_req, uint32_t error_code, handle *h_errmsg);


int32_t turns_utils_init_allocation_context(
        turns_instance_t *instance, turns_allocation_t *context, 
        turns_rx_stun_pkt_t *stun_pkt);


int32_t turns_utils_deinit_allocation_context(turns_allocation_t *alloc);


int32_t turns_utils_setup_allocation(turns_allocation_t *context);


int32_t turns_utils_start_alloc_timer(turns_allocation_t *alloc);


int32_t turns_utils_stop_alloc_timer(turns_allocation_t *alloc);


int32_t turns_utils_start_permission_timer(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_stop_permission_timer(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_start_channel_binding_timer(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_stop_channel_binding_timer(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_verify_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code);


int32_t turns_utils_start_nonce_stale_timer(turns_allocation_t *alloc);


int32_t turns_utils_stop_nonce_stale_timer(turns_allocation_t *alloc);


int32_t turns_utils_verify_info_from_refresh_request(
                turns_allocation_t *alloc, handle h_msg, uint32_t *error_code);


int32_t turns_utils_handle_create_permission_request(
                                turns_allocation_t *alloc, handle h_msg);


int32_t turns_utils_refresh_permission(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_install_permission(turns_allocation_t *alloc, 
                                    uint16_t channel, stun_inet_addr_t *addr);


int32_t turns_utils_uninstall_permission(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_handle_channel_bind_request(
                                turns_allocation_t *alloc, handle h_msg);


turns_permission_t *turns_utils_validate_allocation_channel_binding(
                                        turns_allocation_t *alloc, handle arg);


turns_permission_t *turns_utils_validate_permission_handle(
                                        turns_allocation_t *alloc, handle arg);


turns_permission_t *turns_utils_search_for_permission(
                        turns_allocation_t *alloc, stun_inet_addr_t addr);


int32_t turns_utils_install_channel_binding(
        turns_allocation_t *alloc, turns_permission_t *perm, uint16_t channel);


int32_t turns_utils_refresh_channel_binding(
                turns_allocation_t *alloc, turns_permission_t *perm);


int32_t turns_utils_forward_send_data(turns_allocation_t *alloc, handle h_msg);


int32_t turns_utils_forward_channel_data(
                    turns_allocation_t *alloc, turns_rx_channel_data_t *data);


int32_t turns_utils_forward_udp_data_using_channeldata_msg(
                        turns_allocation_t *alloc, turns_permission_t *perm, 
                        turns_rx_channel_data_t *data);


int32_t turns_utils_forward_udp_data_using_data_ind(
                        turns_allocation_t *alloc, turns_permission_t *perm, 
                        turns_rx_channel_data_t *data);


int32_t turns_utils_calculate_allocation_relayed_data(
                        turns_allocation_t *alloc, uint64_t *ingress_data, 
                        uint64_t *egress_data);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
