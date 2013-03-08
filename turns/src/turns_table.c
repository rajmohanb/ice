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


#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/mman.h>


#include "stun_base.h"
#include "msg_layer_api.h"
#include "stun_txn_api.h"
#include "turns_api.h"
#include "turns_int.h"
#include "turns_utils.h"
#include "turns_table.h"




typedef struct turns_alloc_node {
    bool_t used;
    sem_t  lock;
    turns_allocation_t context;
} turns_alloc_node_t;



typedef struct {
    sem_t   mutex;
    uint32_t mmap_len;
    uint32_t max_allocs;
    uint32_t cur_allocs;
    turns_alloc_node_t *alloc_list;
} turns_alloc_table_t;




int32_t turns_create_table(uint32_t max_allocs, handle *h_table)
{
    uint32_t size, fd, i;
    turns_alloc_table_t *table = NULL;
    char zero = 0;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    /** open file for shared memory access */
    fd = open(TURNS_MMAP_FILE_PATH, O_RDWR | O_CREAT);
    if (fd == -1)
    {
        perror("open");
        printf("TURNS: opening the shared memory file failed\n");
        return STUN_INT_ERROR;
    }

    /** calculate the size to be allocated */
    size = sizeof(turns_alloc_table_t);
    size += max_allocs * sizeof(turns_alloc_node_t);

    /** write some data TODO - need to optimize? */
    for (i = 0; i < size; i++) write(fd, &zero, sizeof(char));

    /** allocate shared memory */
    table = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (table == (void *) -1)
    {
        perror("mmap:");
        printf("TURNS: allocation of shared memory failed\n");
        return STUN_MEM_ERROR;
    }

    ICE_LOG(LOG_SEV_INFO, 
            "Size of each allocation: [%d] bytes", sizeof(turns_allocation_t));
    ICE_LOG(LOG_SEV_INFO, 
            "Allocated shared memory of size: [%d] bytes", size);

    close(fd);
    table->alloc_list = (void *) (table + sizeof(turns_alloc_table_t));
    table->mmap_len = size;
    table->max_allocs = max_allocs;
    table->cur_allocs = 0;

    ICE_LOG(LOG_SEV_DEBUG, "table = %p", table);
    ICE_LOG(LOG_SEV_DEBUG, "table alloc list = %p", table->alloc_list);

    *h_table = table;

    return STUN_OK;
}



int32_t turns_destroy_table(handle h_table)
{
    turns_alloc_table_t *table = h_table;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    /** TODO: check return value */
    munmap(table, table->mmap_len);

    return STUN_OK;
}



int32_t turns_table_does_node_exist(handle h_table, turns_allocation_t *alloc)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node;
    uint32_t i;

    if ((h_table == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    if (table->cur_allocs == 0) return STUN_NOT_FOUND;

    node = (turns_alloc_node_t *) table->alloc_list;

    for (i = 0; i < table->max_allocs; i++)
    {
        if (alloc == &node->context)
        {
            if (node->used == true)
            {
                ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context found");
                return STUN_OK;
            }
            else
            {
                break;
            }
        }

        node++;
    }

    ICE_LOG (LOG_SEV_ERROR, 
            "[STUN TXN] Stun txn handle NOT FOUND while searching");
    
    return STUN_NOT_FOUND;
}



int32_t turns_table_find_node(handle h_table, 
        stun_inet_addr_t *src, handle transport_param, 
        stun_transport_protocol_type_t protocol, turns_allocation_t **alloc)
{
    int32_t status, i;
    turns_alloc_node_t *node = NULL;
    turns_allocation_t *context = NULL;
    turns_alloc_table_t *table = (turns_alloc_table_t *)h_table;

    if ((h_table == NULL) || (src == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    if (table->cur_allocs == 0) return STUN_NOT_FOUND;

    node = (turns_alloc_node_t *) table->alloc_list;

    for (i = 0; i < table->max_allocs; i++)
    {
        context = &node->context;

        if ((context->protocol == protocol) &&
            (context->transport_param == transport_param) &&
            (context->client_addr.host_type == src->host_type) &&
            (context->client_addr.port == src->port) &&
            (turns_utils_host_compare(context->client_addr.ip_addr, 
                                      src->ip_addr, src->host_type)))
        {
            ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context found");
            *alloc = context;
            return STUN_OK;
        }

        node++;
    }

    ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context NOT found");
    
    return STUN_NOT_FOUND;
}



turns_allocation_t *turns_table_create_allocation(handle h_table)
{
    uint32_t i;
    turns_alloc_node_t *node = NULL;
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;

    if (h_table == NULL) return NULL;

    if (table->cur_allocs >= table->max_allocs) return NULL;

    node = table->alloc_list;

    for(i = 0; i < table->max_allocs; i++)
        if(node->used == false)
            break;
        else
            node++;

    /** should never land here... this has been taken care of above */
    if (i == table->max_allocs) return NULL;

    /** this node is now taken */
    node->used = true;

    /** TODO - should we do anything with the lock here? */

    /** update the table parameters */
    table->cur_allocs += 1;

    printf("Number of allocations now: %d\n", table->cur_allocs);

    return &node->context;
}



int32_t turns_table_delete_allocation(
                    handle h_table, turns_allocation_t *alloc)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node;
    uint32_t i;

    if ((h_table == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    if (table->cur_allocs == 0) return STUN_NOT_FOUND;

    node = (turns_alloc_node_t *) table->alloc_list;

    for (i = 0; i < table->max_allocs; i++)
    {
        if (alloc == &node->context)
        {
            if (node->used == false)
                ICE_LOG (LOG_SEV_ERROR, 
                        "[TURNS] Fixme!!!! The allocation is already usused?");
            
            node->used = false;
            table->cur_allocs -= 1;
            printf("Number of allocations now: %d\n", table->cur_allocs);
            return STUN_OK;
        }

        node++;
    }

    ICE_LOG (LOG_SEV_ERROR, 
            "[STUN TXN] Stun txn handle NOT FOUND while searching");
    
    return STUN_NOT_FOUND;
}



int32_t turns_table_find_node_for_relayed_transport_address(
        handle h_table, handle transport_param,
        stun_transport_protocol_type_t protocol, turns_allocation_t **alloc)
{
    int32_t status, i;
    turns_alloc_node_t *node = NULL;
    turns_allocation_t *context = NULL;
    turns_alloc_table_t *table = (turns_alloc_table_t *)h_table;

    if ((h_table == NULL) || (transport_param == NULL) || (alloc == NULL))
        return STUN_INVALID_PARAMS;

    if (table->cur_allocs == 0) return STUN_NOT_FOUND;

    node = (turns_alloc_node_t *) table->alloc_list;

    for (i = 0; i < table->max_allocs; i++)
    {
        context = &node->context;
        if ((context->protocol == protocol) && 
                (context->relay_sock == (int)transport_param))
        {
            ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation "\
                    "context found for relayed transport address");
            *alloc = context;
            return STUN_OK;
        }

        node++;
    }

    ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context NOT "\
            "found for relayed transport address");
    
    return STUN_NOT_FOUND;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
