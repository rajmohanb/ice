/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                  Copyright (C) 2009-2012, Rajmohan Banavi                    *
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
#include "stun_msg.h"
#include "stun_txn_api.h"
#include "stun_txn_int.h"


int32_t stun_txn_utils_generate_txn_id (u_char *txn_id, uint32_t bytes)
{
    if (platform_get_random_data(txn_id, bytes) == true)
        return STUN_OK;

    ICE_LOG(LOG_SEV_ERROR, "Platform function to get random data failed .");
    ICE_LOG(LOG_SEV_ERROR, "platform_get_random_data()");

    return STUN_INT_ERROR;
}



int32_t stun_txn_utils_killall_timers (stun_txn_context_t *txn_ctxt)
{
    int32_t status;

    if (txn_ctxt->h_rto_timer)
    {
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rto_timer);
        if (status == STUN_OK)
        {
            txn_ctxt->h_rto_timer = NULL;
            stun_free(txn_ctxt->rto_params);
        }
        
        txn_ctxt->rto_params = NULL;
    }

    if (txn_ctxt->h_rm_timer)
    {
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_rm_timer);
        if (status == STUN_OK)
        {
            txn_ctxt->h_rm_timer = NULL;
            stun_free(txn_ctxt->rm_params);
        }

        txn_ctxt->rm_params = NULL;
    }

    if (txn_ctxt->h_overall_timer)
    {
        status = txn_ctxt->instance->stop_timer_cb(txn_ctxt->h_overall_timer);
        if (status == STUN_OK)
        {
            txn_ctxt->h_overall_timer = NULL;
            stun_free(txn_ctxt->oall_params);
        }

        txn_ctxt->oall_params = NULL;
    }

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
