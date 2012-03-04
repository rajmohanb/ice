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
#include "conn_check_api.h"
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
        ice_cp_initiate_check,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    },
    /** ICE_CP_INPROGRESS */
    {
        ice_cp_unfreeze,
        ice_cp_ignore_msg,
        ice_cp_check_succeeded,
        ice_cp_check_failed,
    },
    /** ICE_CP_SUCCEEDED */
    {
        ice_cp_unfreeze,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
        ice_cp_ignore_msg,
    },
    /** ICE_CP_FAILED */
    {
        ice_cp_unfreeze,
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


int32_t ice_cp_initiate_check(ice_cand_pair_t *cp, handle h_msg)
{
    int32_t status = ice_cand_pair_utils_init_connectivity_check(cp);
    if (status != STUN_OK)
    {
        ICE_LOG (LOG_SEV_ERROR, 
                "[ICE CAND PAIR] Sending of connectivity check failed");
        
        cp->state = ICE_CP_FAILED;

        return status;
    }

    cp->state = ICE_CP_INPROGRESS;

    return STUN_OK;
}


int32_t ice_cp_check_succeeded(ice_cand_pair_t *cp, handle h_msg)
{
    cp->state = ICE_CP_SUCCEEDED;

    return STUN_OK;
}


int32_t ice_cp_check_failed(ice_cand_pair_t *cp, handle h_msg)
{
    cp->state = ICE_CP_FAILED;

    return STUN_OK;
}


int32_t ice_cp_ignore_msg(ice_cand_pair_t *cp, handle h_msg)
{
    return STUN_OK;
}


int32_t ice_cand_pair_fsm_inject_msg(ice_cand_pair_t *cp, 
                                    ice_cp_event_t event, handle h_msg)
{
    int32_t status;
    ice_cp_state_t old_state;
    ice_cand_pair_fsm_handler handler;

    old_state = cp->state;
    handler = ice_cand_pair_fsm[cp->state][event];

    if (!handler)
        return STUN_INVALID_PARAMS;

    status = handler(cp, h_msg);

    if (old_state != cp->state)
    {
        ICE_LOG(LOG_SEV_DEBUG,
                "[ICE CAND PAIR] Candidate pair state changed from %d to %d",
                old_state, cp->state);
    }

    return status;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
