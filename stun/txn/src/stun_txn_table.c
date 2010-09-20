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

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_msg.h"
#include "stun_txn_api.h"
#include "stun_txn_int.h"
#include "stun_txn_table.h"

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
    ICE_LOG(LOG_SEV_INFO, msg_str":STUN txn ID[%s]", txn_log_buf);\
} while(0)
#endif

int32_t stun_txn_create_table(uint32_t size, handle *h_table)
{
    stun_txn_table_t *table;

    if (h_table == NULL)
        return STUN_INVALID_PARAMS;

    table = (stun_txn_table_t *) stun_calloc 
                (1, (size * sizeof(stun_txn_table_t)));
    if (table == NULL)
        return STUN_MEM_ERROR;

    *h_table = table;

    return STUN_OK;
}

int32_t stun_txn_destroy_table(handle h_table)
{
    if (h_table == NULL)
        return STUN_INVALID_PARAMS;

    stun_free(h_table);

    return STUN_OK;
}


int32_t stun_txn_table_txn_exists(handle h_table, handle h_txn)
{
    stun_txn_table_t *node = (stun_txn_table_t *) h_table;
    uint32_t i;

    for (i = 0; i < STUN_TXN_TABLE_MAX_TXNS; i++)
    {
        if (h_txn == node->h_txn)
        {
            ICE_LOG (LOG_SEV_INFO, "Stun txn handle found while searching");
            return STUN_OK;
        }
        node++;
    }

    ICE_LOG (LOG_SEV_ERROR, "Stun txn handle NOT FOUND while searching");
    return STUN_NOT_FOUND;
}


int32_t stun_txn_table_find_txn(handle h_table, handle h_msg, handle *h_txn)
{
    u_char txn_id[STUN_TXN_ID_BYTES];
    stun_txn_table_t *node = (stun_txn_table_t *) h_table;
    uint32_t i;

    if ((h_table == NULL) || (h_msg == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    stun_msg_get_txn_id(h_msg, txn_id);

#ifdef DEBUG
    LOG_STUN_TRXN_ID_STR("Searching for Transaction ID in table", txn_id);
#endif

    for (i = 0; i < STUN_TXN_TABLE_MAX_TXNS; i++)
    {
#ifdef DEBUG
	    LOG_STUN_TRXN_ID_STR("Table Entry", node->trans_id);
    	ICE_LOG (LOG_SEV_INFO, "node->h_txn-----> %p\n", node->h_txn);
#endif

        if (stun_memcmp(txn_id, node->trans_id, STUN_TXN_ID_BYTES) == 0)
        {
            *h_txn = node->h_txn;
            ICE_LOG (LOG_SEV_INFO, "Table entry match found");
            return STUN_OK;
        }

        node++;
    }

    ICE_LOG (LOG_SEV_INFO, "Table entry match NOT found");
    return STUN_NOT_FOUND;
}

int32_t stun_txn_table_add_txn(handle h_table, handle h_txn)
{
    stun_txn_table_t *node = (stun_txn_table_t *) h_table;
    stun_txn_context_t *txn_ctxt = (stun_txn_context_t *) h_txn;
    uint32_t i;

    if ((h_table == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    for (i = 0; i < STUN_TXN_TABLE_MAX_TXNS; i++)
    {
        if (node->h_txn == NULL)
        {
            stun_memcpy(node->trans_id, txn_ctxt->txn_id, STUN_TXN_ID_BYTES);
            node->h_txn = h_txn;

#ifdef DEBUG
	        LOG_STUN_TRXN_ID_STR("Added Transaction ID to table", node->trans_id);
            ICE_LOG (LOG_SEV_INFO, "node->h_txn -----> %p\n", node->h_txn);
#endif
            return STUN_OK;
        }
       
        node++; 
    }

    return STUN_INT_ERROR;
}

int32_t stun_txn_table_remove_txn(handle h_table, handle h_txn)
{
    stun_txn_table_t *node = (stun_txn_table_t *) h_table;
    stun_txn_context_t *txn_ctxt = (stun_txn_context_t *) h_txn;
    uint32_t i;

    if ((h_table == NULL) || (h_txn == NULL))
        return STUN_INVALID_PARAMS;

    for (i = 0; i < STUN_TXN_TABLE_MAX_TXNS; i++)
    {
#ifdef DEBUG
	    LOG_STUN_TRXN_ID_STR("Table entry", node->trans_id);
        ICE_LOG (LOG_SEV_INFO, "node->h_txn -----> %p\n", node->h_txn);
#endif
        if (node->h_txn == txn_ctxt)
        {
#ifdef DEBUG
	        LOG_STUN_TRXN_ID_STR("Removed Transaction ID from table", node->trans_id);
            ICE_LOG (LOG_SEV_INFO, "node->h_txn -----> %p\n", node->h_txn);
#endif

            stun_memset(node->trans_id, 0, STUN_TXN_ID_BYTES);
            node->h_txn = NULL;

            return STUN_OK;
        }
        node++; 
    }

    return STUN_NOT_FOUND;
}

/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
