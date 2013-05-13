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

#ifndef TURNS_TABLE__H
#define TURNS_TABLE__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/



int32_t turns_create_table(uint32_t max_allocs, handle *h_table);


int32_t turns_destroy_table(handle h_table);


int32_t turns_table_does_node_exist(handle h_table, turns_allocation_t *alloc);


int32_t turns_table_find_node(handle h_table, 
        stun_inet_addr_t *src, handle transport_param, 
        stun_transport_protocol_type_t protocol, turns_allocation_t **alloc);


turns_allocation_t *turns_table_create_allocation(handle h_table);


int32_t turns_table_delete_allocation(
                    handle h_table, turns_allocation_t *alloc);


int32_t turns_table_find_node_for_relayed_transport_address(
        handle h_table, handle transport_param,
        stun_transport_protocol_type_t protocol, turns_allocation_t **alloc);


typedef void (*turns_alloc_iteration_cb)(handle h_alloc, turns_allocation_t *alloc);


int32_t turns_table_iterate(handle h_table, turns_alloc_iteration_cb iter_cb);


int32_t turns_table_init_allocations(handle h_table);


int32_t turns_table_deinit_allocations(handle h_table);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
