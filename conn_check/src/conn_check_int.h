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

#ifndef CONN_CHECK_INT__H
#define CONN_CHECK_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#define MAX_STR_LEN                 763
#define CONN_CHECK_TXN_TABLE_SIZE   25


typedef enum
{
    CC_STUN_TXN_TIMER = 0,
    /** that's all we have as of now */
} cc_timer_type_t;


typedef struct {
    handle h_instance;
    handle h_cc_session;
    cc_timer_type_t type;
    handle timer_id;
    handle arg;
} cc_timer_params_t;



typedef enum 
{
    CONN_CHECK_REQ = 0,
    CONN_CHECK_OK_RESP,
    CONN_CHECK_ERROR_RESP,
    CONN_CHECK_TIMEOUT,
    CONN_CHECK_EVENT_MAX,
} conn_check_event_t;


typedef struct 
{
    /** transaction instance handle */
    handle h_txn_inst;

    conn_check_session_nwk_send_cb nwk_send_cb;
    conn_check_session_start_timer_cb start_timer_cb;
    conn_check_session_stop_timer_cb stop_timer_cb;

    /** session list */
    handle ah_session[CONN_CHECK_MAX_CONCURRENT_SESSIONS];

} conn_check_instance_t;


typedef struct 
{
    conn_check_instance_t *instance;

    /** conn check credentials */
    uint32_t local_user_len;
    uint32_t local_pwd_len;
    u_char local_user[STUN_MAX_USERNAME_LEN];
    u_char local_pwd[STUN_MAX_PASSWORD_LEN];

    uint32_t peer_user_len;
    uint32_t peer_pwd_len;
    u_char peer_user[STUN_MAX_USERNAME_LEN];
    u_char peer_pwd[STUN_MAX_PASSWORD_LEN];

    /** peer stun server */
    stun_inet_addr_type_t stun_server_type;
    u_char stun_server[STUN_IP_ADDR_MAX_LEN];
    uint32_t stun_port;

    cc_session_type_t sess_type;
    handle app_param;

    handle transport_param;

    /** behavioral params */
    bool_t nominated;
    bool_t controlling_role;
    uint32_t prflx_cand_priority;

    /** session state */
    conn_check_session_state_t state;

    handle h_txn;
    handle h_req;
    handle h_resp;

    stun_inet_addr_t prflx_addr;

    /** connectivity check result */
    bool_t cc_succeeded;
    uint32_t error_code;

} conn_check_session_t;


typedef int32_t (*conn_check_session_fsm_handler) 
                    (conn_check_session_t *session, handle h_msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
