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
#include <pthread.h>
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
    turns_allocation_t context;
} turns_alloc_node_t;



typedef struct {
    pthread_rwlock_t table_lock;
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

    /** remove shared memory object if it existed */
    shm_unlink(TURNS_MMAP_FILE_PATH);

    /** open file for shared memory access */
    fd = shm_open(TURNS_MMAP_FILE_PATH, O_RDWR | O_CREAT, S_IRWXU);
    if (fd == -1)
    {
        perror("shared memory open");
        ICE_LOG(LOG_SEV_ALERT, "TURNS: opening the shared memory file failed");
        return STUN_INT_ERROR;
    }

    /** calculate the size to be allocated */
    size = sizeof(turns_alloc_table_t);
    size += max_allocs * sizeof(turns_alloc_node_t);

    if (ftruncate(fd, size) < 0)
    {
        perror("shared memory ftruncate");
        ICE_LOG(LOG_SEV_ALERT, "TURNS: Truncating the shared mem file failed");
        close(fd);
        return STUN_INT_ERROR;
    }

    /** write some data TODO - need to optimize? */ 
    for (i = 0; i < size; i++) write(fd, &zero, sizeof(char));
    //write(fd, &zero, size);

    /**
     * TODO - the allocation size is desired to be in multiple of the PAGESIZE
     * since internally mmap deals only with pages, and it is desirable that
     * they are aligned to the page boundary. Typical page sizes - 4096/8192.
     */

    /** allocate shared memory */
    table = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (table == (void *) -1)
    {
        perror("shared mem mmap:");
        ICE_LOG(LOG_SEV_ALERT, "TURNS: allocation of shared memory failed");
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

    /** TODO: Do we need to use non-default attr? */
    if (pthread_rwlock_init(&table->table_lock, NULL) != 0)
    {
        /** TODO - unmmap, etc */
        return STUN_INT_ERROR;
    }

    ICE_LOG(LOG_SEV_DEBUG, "table = %p", table);
    ICE_LOG(LOG_SEV_DEBUG, "table alloc list = %p", table->alloc_list);

    *h_table = table;

    return STUN_OK;
}



int32_t turns_destroy_table(handle h_table)
{
    turns_alloc_table_t *table = h_table;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    if (munmap(table, table->mmap_len) != 0)
    {
        perror("turns munmap");
        ICE_LOG(LOG_SEV_ALERT, "Shared memory release failed");
        return STUN_INT_ERROR;
    }

    pthread_rwlock_destroy(&table->table_lock);

    return STUN_OK;
}


#if 0
int32_t turns_destroy_table_with_callback(handle h_table)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node;
    uint32_t i;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    node = (turns_alloc_node_t *) table->alloc_list;

    /** 
     * for each allocation in the table, inform 
     * the application using the event notifier 
     */
    for (i = 0; i < table->max_allocs; i++)
    {
        if (&node->context)
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


    if (munmap(table, table->mmap_len) != 0)
    {
        perror("turns munmap");
        ICE_LOG(LOG_SEV_ALERT, "Shared memory release failed");
        return STUN_INT_ERROR;
    }

    return STUN_OK;
}
#endif



int32_t turns_table_iterate(handle h_table, turns_alloc_iteration_cb iter_cb)
{
    turns_alloc_table_t *table = (turns_alloc_table_t *) h_table;
    turns_alloc_node_t *node;
    uint32_t i;

    if (h_table == NULL) return STUN_INVALID_PARAMS;
    if (table->cur_allocs == 0) return STUN_OK;
    node = (turns_alloc_node_t *) table->alloc_list;

    pthread_rwlock_rdlock(&table->table_lock);

    for (i = 0; i < table->max_allocs; i++)
    {
        if (node->used == true)
            iter_cb(h_table, &(node->context)); /** callback */

        node++;
    }

    pthread_rwlock_unlock(&table->table_lock);

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

    pthread_rwlock_rdlock(&table->table_lock);

    for (i = 0; i < table->max_allocs; i++)
    {
        if (alloc == &node->context)
        {
            if (node->used == true)
            {
                pthread_rwlock_unlock(&table->table_lock);
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

    pthread_rwlock_unlock(&table->table_lock);
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

    pthread_rwlock_rdlock(&table->table_lock);

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
            pthread_rwlock_unlock(&table->table_lock);
            ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation context found");
            *alloc = context;
            return STUN_OK;
        }

        node++;
    }

    pthread_rwlock_unlock(&table->table_lock);
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

    pthread_rwlock_wrlock(&table->table_lock);

    for(i = 0; i < table->max_allocs; i++)
        if(node->used == false)
            break;
        else
            node++;

    /** should never land here... this has been taken care of above */
    if (i == table->max_allocs)
    {
        pthread_rwlock_unlock(&table->table_lock);
        return NULL;
    }

    /** this node is now taken */
    node->used = true;

    /** TODO - should we do anything with the lock here? */

    /** update the table parameters */
    table->cur_allocs += 1;

    ICE_LOG(LOG_SEV_NOTICE, 
            "Number of allocations now: %d\n", table->cur_allocs);

    pthread_rwlock_unlock(&table->table_lock);

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

    pthread_rwlock_wrlock(&table->table_lock);

    for (i = 0; i < table->max_allocs; i++)
    {
        if (alloc == &node->context)
        {
            if (node->used == false)
            {
                ICE_LOG (LOG_SEV_ERROR, 
                        "[TURNS] Fixme!!!! The allocation is already usused?");
            }
            else
            {
                node->used = false;
                table->cur_allocs -= 1;
                ICE_LOG(LOG_SEV_NOTICE, 
                    "Number of allocations now: %d", table->cur_allocs);
            }
            pthread_rwlock_unlock(&table->table_lock);
            return STUN_OK;
        }

        node++;
    }

    pthread_rwlock_unlock(&table->table_lock);
    ICE_LOG (LOG_SEV_INFO, 
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

    pthread_rwlock_rdlock(&table->table_lock);

    for (i = 0; i < table->max_allocs; i++)
    {
        context = &node->context;
        if ((context->protocol == protocol) && 
                (context->relay_sock == (int)transport_param))
        {
            *alloc = context;
            pthread_rwlock_unlock(&table->table_lock);
            ICE_LOG (LOG_SEV_INFO, "[TURNS] Allocation "\
                    "context found for relayed transport address");
            return STUN_OK;
        }

        node++;
    }

    pthread_rwlock_unlock(&table->table_lock);
    ICE_LOG (LOG_SEV_DEBUG, "[TURNS] Allocation context NOT "\
            "found for relayed transport address");
    
    return STUN_NOT_FOUND;
}



int32_t turns_table_init_allocations(handle h_table)
{
    int32_t status, i;
    turns_alloc_node_t *node = NULL;
    turns_allocation_t *context = NULL;
    turns_alloc_table_t *table = (turns_alloc_table_t *)h_table;
    pthread_mutexattr_t mattr;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    node = (turns_alloc_node_t *) table->alloc_list;

    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);

    for (i = 0; i < table->max_allocs; i++)
    {
        context = &node->context;

        // memset(context, 0, sizeof(turns_alloc_node_t));
        pthread_mutex_init(&context->lock, &mattr);

        node++;
    }

    return STUN_OK;
}



int32_t turns_table_deinit_allocations(handle h_table)
{
    int32_t status, i;
    turns_alloc_node_t *node = NULL;
    turns_allocation_t *context = NULL;
    turns_alloc_table_t *table = (turns_alloc_table_t *)h_table;

    if (h_table == NULL) return STUN_INVALID_PARAMS;

    node = (turns_alloc_node_t *) table->alloc_list;

    for (i = 0; i < table->max_allocs; i++)
    {
        context = &node->context;

        pthread_mutex_destroy(&context->lock);

        node++;
    }

    return STUN_OK;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
