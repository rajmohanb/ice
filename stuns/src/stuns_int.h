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

#ifndef STUNS_INT__H
#define STUNS_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef enum
{
    /** timer started by turn transactions */
    STUNS_STUN_TXN_TIMER = 0,
    
    /** timers internal to turn */
    //TURN_ALLOC_REFRESH_TIMER,
    //TURN_PERM_REFRESH_TIMER,
    //TURN_CHNL_REFRESH_TIMER,
    //TURN_KEEP_ALIVE_TIMER,

    /** that's all we have as of now */
} stuns_timer_type_t;


typedef struct {
    handle h_instance;
    handle h_turn_session;
    stuns_timer_type_t type;
    handle timer_id;
    handle arg;
} stuns_timer_params_t;


typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    /** list of allocations */
    //handle  h_table;

    /** software client name and version */
    uint32_t client_name_len;
    u_char *client_name;

    /** timer and socker callbacks */
    stuns_nwk_send_cb nwk_send_cb;
    stuns_start_timer_cb start_timer_cb;
    stuns_stop_timer_cb stop_timer_cb;

} stuns_instance_t;




/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
