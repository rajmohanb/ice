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
#include "ice_api.h"
#include "ice_int.h"
#include "ice_utils.h"
#include "ice_cand_pair_fsm.h"


static ice_cand_pair_fsm_handler 
    ice_cand_pair_fsm[ICE_CP_STATE_MAX][ICE_CP_EVENT_MAX] =
{
    /** ICE_CP_FROZEN */
    {
        ice_cp_unfreeze,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    },
    /** ICE_CP_WAITING */
    {
        ice_cp_ignore_msg,
        ice_cp_initiate_cc,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    },
    /** ICE_CP_INPROGRESS */
    {
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_cc_succeeded,
        ice_cp_cc_failed,
    },
    /** ICE_CP_SUCCEEDED */
    {
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    },
    /** ICE_CP_FAILED */
    {
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    }
};


int32_t ice_cp_unfreeze(ice_cand_pair_t *cp, handle h_msg)
{
    cp->state = ICE_CP_WAITING;
    
    return STUN_OK;
}


int32_t ice_cp_initiate_cc(ice_cand_pair_t *cp, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_cp_cc_succeeded(ice_cand_pair_t *cp, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_cp_cc_failed(ice_cand_pair_t *cp, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_cp_ignore_msg(ice_cand_pair_t *cp, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_cand_pair_fsm_inject_msg(ice_cand_pair_t *session, 
                                    ice_cp_event_t event, handle h_msg)
{
    ice_cand_pair_fsm_handler handler;

    handler = ice_cand_pair_fsm[session->state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    return handler(session, h_msg);
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
