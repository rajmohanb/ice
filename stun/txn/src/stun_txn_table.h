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

#ifndef STUN_TXN_TABLE__H
#define STUN_TXN_TABLE__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef struct {
    handle h_txn;
    u_char trans_id[STUN_TXN_ID_BYTES];
} stun_txn_table_node_t;

typedef struct {
    uint32_t size;
    uint32_t count;
    stun_txn_table_node_t *nodes;
} stun_txn_table_t;

#define STUN_TXN_TABLE_MAX_TXNS     25

int32_t stun_txn_create_table(uint32_t size, handle *h_table);

int32_t stun_txn_destroy_table(handle h_table);

int32_t stun_txn_table_txn_exists(handle h_table, handle h_txn);

int32_t stun_txn_table_find_txn(handle h_table, handle h_msg, handle *h_txn);

int32_t stun_txn_table_add_txn(handle h_table, handle h_txn);

int32_t stun_txn_table_remove_txn(handle h_table, handle h_txn);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
