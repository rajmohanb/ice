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



typedef struct turns_alloc_node {
    struct turns_alloc_node *next;
    struct turns_alloc_node *prev;
    handle context;
} turns_alloc_node_t;



typedef struct {
    uint32_t count;
    turns_alloc_node_t *head;
} turns_alloc_table_t;



int32_t turns_create_table(handle *h_table);


int32_t turns_destroy_table(handle h_table);


int32_t turns_table_does_node_exist(handle h_table, turns_allocation_t *alloc);


int32_t turns_table_find_node(handle h_table, 
                    turns_rx_stun_pkt_t *pkt, turns_allocation_t **alloc);


int32_t turns_table_add_node(handle h_table, turns_allocation_t *alloc);


int32_t turns_txn_table_remove_node(handle h_table, turns_allocation_t *alloc);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
