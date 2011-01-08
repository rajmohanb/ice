/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2011, MindBricks Technologies               *
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

int32_t stun_txn_utils_generate_txn_id(u_char *txn_id, uint32_t bytes)
{
    if (platform_get_random_data(txn_id, bytes) == true)
        return STUN_OK;

    ICE_LOG(LOG_SEV_ERROR, "Platform function to get random data failed .");
    ICE_LOG(LOG_SEV_ERROR, "platform_get_random_data()");

    return STUN_INT_ERROR;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
