/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
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
#include "stun_txn_api.h"
#include "stun_binding_api.h"
#include "stun_binding_int.h"
#include "stun_binding_utils.h"


int32_t stun_binding_utils_create_msg(stun_msg_type_t msg_type, handle *h_req)
{
    handle h_msg;
    int32_t status;

    status = stun_msg_create(msg_type, STUN_METHOD_BINDING, &h_msg);
    if (status != STUN_OK) return status;

    *h_req = h_msg;

    return status;
}



/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
