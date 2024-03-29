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

#ifndef CONN_CHECK_API__H
#define CONN_CHECK_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define CONN_CHECK_MAX_CONCURRENT_SESSIONS  50
#define STUN_MAX_USERNAME_LEN               128
#define STUN_MAX_PASSWORD_LEN               128
#define STUN_MAX_REALM_LEN                  64
#define STUN_IP_ADDR_MAX_LEN                46

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
    CC_OG_TERMINATED,

    CC_IC_IDLE,
    CC_IC_WAITING,
    CC_IC_TERMINATED,

    CC_STATE_MAX,
} conn_check_session_state_t;


typedef int32_t (*conn_check_session_nwk_send_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, handle app_param);
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


typedef struct {

    /** role: controlling or controlled */
    bool_t controlling_role;

    /** conn check: nominated one or not */
    bool_t nominated;

    /** tie-breaker value */
    uint64_t tie_breaker;

    /** candidate priority for peer reflexive candidate */
    uint32_t prflx_cand_priority;

} conn_check_session_params_t;



typedef struct {
    bool_t check_succeeded;
    bool_t nominated;
    bool_t controlling_role;
    uint32_t error_code;
    uint32_t priority;
    stun_inet_addr_t mapped_addr;
} conn_check_result_t;



typedef struct
{
    /** parsed stun packet handle */
    handle h_msg;

    /** transport parameter */
    handle transport_param;

    /** source address of stun packet */
    stun_inet_addr_t src;

} conn_check_rx_pkt_t;


/******************************************************************************/

int32_t conn_check_create_instance(handle *h_inst);

int32_t conn_check_instance_set_callbacks(handle h_inst, 
                                conn_check_instance_callbacks_t *cb);

int32_t conn_check_instance_set_client_software_name(handle h_inst, 
                                                u_char *client, uint32_t len);

int32_t conn_check_destroy_instance(handle h_inst);

int32_t conn_check_create_session(handle h_inst, 
                cc_session_type_t sess_type, handle *h_session);

int32_t conn_check_session_set_peer_transport_params(
        handle h_inst, handle h_session, stun_inet_addr_type_t stun_svr_type, 
        u_char *stun_svr_ip, uint32_t port);

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

int32_t conn_check_cancel_session(handle h_inst, handle h_session);


int32_t conn_check_destroy_session(handle h_inst, handle h_session);


int32_t conn_check_session_inject_received_msg(
            handle h_inst, handle h_session, conn_check_rx_pkt_t *rx_msg);

int32_t conn_check_instance_inject_timer_event(
                    handle h_timerid, handle arg, handle *h_session);

int32_t conn_check_find_session_for_recv_msg(handle h_inst, 
                                        handle h_msg, handle *h_session);

int32_t conn_check_session_initiate_check(handle h_inst, handle h_session);

int32_t conn_check_session_set_session_params(handle h_inst, 
                        handle h_session, conn_check_session_params_t *params);

int32_t conn_check_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance);

int32_t conn_check_session_get_check_result(handle h_inst, 
                                handle h_session, conn_check_result_t *result);

int32_t conn_check_session_send_reponse(
        handle h_inst, handle h_session, uint32_t resp_code);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
