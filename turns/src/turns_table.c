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
#include "turns_table.h"


#ifdef DEBUG
#define LOG_STUN_TRXN_ID_STR(msg_str, txn_id) do {		\
    u_char txn_log_buf[(STUN_TXN_ID_BYTES * 2) + 1] = {0};	\
    uint32_t i = 0, n = 0, bc = 0;				\
    for (i = 0, n = 0, bc = 0; i < STUN_TXN_ID_BYTES; i++) {	\
       bc = stun_snprintf((char *)txn_log_buf + n,		\
		sizeof(txn_log_buf) - n - 1,			\
		"%x", txn_id[i]);				\
       n += bc;							\
    }								\
    txn_log_buf[(STUN_TXN_ID_BYTES * 2)] = '\0';		\
    ICE_LOG(LOG_SEV_DEBUG, msg_str":STUN txn ID[%s]", txn_log_buf);\
} while(0)
#endif



int32_t turns_create_table(handle *h_table)
{
    turns_alloc_table_t *table = NULL;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    table = (turns_alloc_table_t *) stun_calloc (1, sizeof(turns_alloc_table_t));
    if (table == NULL) return STUN_MEM_ERROR;

    table->count = 0;
    table->head = NULL;

    *h_table = table;

    return STUN_OK;
}



int32_t turns_destroy_table(handle h_table)
{
    turns_alloc_table_t *table = h_table;
    turns_alloc_node_t *node, *temp;

    if (h_table == NULL) return STUN_INVALID_PARAMS;
    node = table->head;

    /** free all the nodes */
    while(node)
    {
        temp = node;
        node = node->next;

        /** TODO - free the allocation */

        stun_free(temp);
    }

    stun_free(table);

    return STUN_OK;
}



int32_t turns_table_does_node_exist(handle h_table, turns_allocation_t *alloc)
{
#if 0
    stun_txn_table_t *table = (stun_txn_table_t *) h_table;
    stun_txn_table_node_t *node = table->nodes;
    uint32_t i;

    for (i = 0; i < table->size; i++)
    {
        if (h_txn == node->h_txn)
        {
            ICE_LOG (LOG_SEV_INFO, 
                    "[STUN TXN] Stun txn handle found while searching");
            return STUN_OK;
        }
        node++;
    }

    ICE_LOG (LOG_SEV_ERROR, 
            "[STUN TXN] Stun txn handle NOT FOUND while searching");
#endif
    return STUN_NOT_FOUND;
}



int32_t turns_table_find_node(handle h_table, 
                    turns_rx_stun_pkt_t *pkt, turns_allocation_t **alloc)
{
    int32_t status;
    turns_alloc_table_t *table = (turns_alloc_table_t *)h_table;
    turns_alloc_node_t *node = table->head;
    turns_allocation_t *context;

    if ((h_table == NULL) || (pkt == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    while(node != NULL)
    {
        context = (turns_allocation_t *)node->context;

        if ((context->protocol == pkt->protocol) &&
            (context->transport_param == pkt->transport_param) &&
            (context->client_addr.host_type == pkt->src.host_type) &&
            (context->client_addr.port == pkt->src.port) &&
            (turns_utils_host_compare(context->client_addr.ip_addr, 
                                      pkt->src.ip_addr, pkt->src.host_type)))
        {
            ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context found");
            *alloc = context;
            return STUN_OK;
        }

        node = node->next;
    }

    ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context NOT found");
    return STUN_NOT_FOUND;
}



int32_t turns_table_add_node(handle h_table, turns_allocation_t *alloc)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node = NULL;

    if ((h_table == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    node = (turns_alloc_node_t *) stun_calloc(1, sizeof(turns_alloc_node_t));
    if(node == NULL) return STUN_MEM_ERROR;

    node->prev = NULL;
    node->next = table->head;
    table->head->prev = node;
    node->context = (handle)alloc;
    table->head = node;

    table->count += 1;

    return STUN_OK;
}



int32_t turns_txn_table_remove_node(handle h_table, turns_allocation_t *alloc)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node;

    if ((h_table == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    node = table->head;
    if(node->context == (handle)alloc)
    {
        table->head = node->next;
        node->next->prev = NULL;

        stun_free(node);
        table->count -= 1;

        return STUN_OK;
    }

    node = node->next;
    while(node)
    {
        if(node->context == (handle)alloc)
        {
            node->prev->next = node->next;
            node->next->prev = node->prev;

            stun_free(node);
            table->count -= 1;

            return STUN_OK;
        }

        node = node->next;
    }

    return STUN_NOT_FOUND;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
