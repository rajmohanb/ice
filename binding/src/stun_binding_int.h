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

#ifndef STUN_BINDING_INT__H
#define STUN_BINDING_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define STUN_BINDING_TXN_TABLE_SIZE     10

typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    stun_binding_session_nwk_send_cb nwk_send_cb;
    stun_binding_session_start_timer_cb start_timer_cb;
    stun_binding_session_stop_timer_cb stop_timer_cb;

    /** session list */
    handle ah_session[STUN_BINDING_MAX_CONCURRENT_SESSIONS];

} stun_binding_instance_t;


typedef struct 
{
    stun_binding_instance_t *instance;

    stun_inet_addr_type_t server_type;
    u_char stun_server[STUN_IP_ADDR_MAX_LEN];
    uint32_t stun_port;

    handle app_param;

    handle transport_param;

    handle h_txn;
    handle h_req;
    handle h_resp;

} stun_binding_session_t;


typedef int32_t (*stun_binding_session_fsm_handler) 
                    (stun_binding_session_t *session, handle h_msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
