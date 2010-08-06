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

#ifndef CONN_CHECK_API__H
#define CONN_CHECK_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define CONN_CHECK_MAX_CONCURRENT_SESSIONS    10
#define STUN_MAX_USERNAME_LEN           128
#define STUN_MAX_PASSWORD_LEN           128
#define STUN_MAX_REALM_LEN              64
#define STUN_IP_ADDR_MAX_LEN            46

/******************************************************************************/

typedef enum
{
    CC_CLIENT_SESSION = 0,
    CC_SERVER_SESSION,
    CC_SESSION_TYPE_MAX,
} cc_session_type_t;

typedef enum 
{
    CC_OG_IDLE = 0,
    CC_OG_CHECKING,
    CC_OG_INPROGRESS,
    CC_OG_TERMINATED,

    CC_IC_IDLE,
    CC_IC_TERMINATED,

    CC_STATE_MAX,
} conn_check_session_state_t;

typedef struct
{
    bool_t cc_succeeded;
    bool_t nominated;

    u_char prflx_ip_addr[STUN_IP_ADDR_MAX_LEN];
    uint32_t prflx_port;

} conn_check_result_t;


typedef int32_t (*conn_check_session_nwk_send_cb) (handle h_msg, 
                        u_char *ip_addr, uint32_t port, handle transport_param, 
                        handle app_param);
typedef handle (*conn_check_session_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*conn_check_session_stop_timer_cb) (handle timer_id);
typedef void (*conn_check_session_state_change_cb) (handle h_inst, 
            handle h_session, conn_check_session_state_t state, handle data);


typedef struct {
    conn_check_session_nwk_send_cb nwk_cb;
    conn_check_session_start_timer_cb start_timer_cb;
    conn_check_session_stop_timer_cb  stop_timer_cb;
    conn_check_session_state_change_cb session_state_cb;
} conn_check_instance_callbacks_t;


typedef struct {
    u_char username[STUN_MAX_USERNAME_LEN];
    u_char password[STUN_MAX_PASSWORD_LEN];
} conn_check_credentials_t;


/******************************************************************************/

int32_t conn_check_create_instance(handle *h_inst);

int32_t conn_check_instance_set_callbacks(handle h_inst, 
                                conn_check_instance_callbacks_t *cb);

int32_t conn_check_destroy_instance(handle h_inst);

int32_t conn_check_create_session(handle h_inst, 
                cc_session_type_t sess_type, handle *h_session);

int32_t conn_check_session_set_peer_transport_params(
        handle h_inst, handle h_session, u_char *stun_svr_ip, uint32_t port);

int32_t conn_check_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param);

int32_t conn_check_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t conn_check_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t conn_check_session_set_local_credentials(handle h_inst, 
                handle h_session, conn_check_credentials_t *cred);

int32_t conn_check_session_set_peer_credentials(handle h_inst, 
                handle h_session, conn_check_credentials_t *cred);

int32_t conn_check_destroy_session(handle h_inst, handle h_session);

int32_t conn_check_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg);

int32_t conn_check_find_session_for_recv_msg(handle h_inst, 
                                        handle h_msg, handle *h_session);

int32_t conn_check_session_initiate_check(handle h_inst, handle h_session);

int32_t conn_check_session_set_nominated(handle h_inst, handle h_session);

int32_t conn_check_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance);

int32_t conn_check_session_get_nominated_state(
                handle h_inst, handle h_session, bool *nominated);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
