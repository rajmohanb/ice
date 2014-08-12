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

#ifndef STUN_BINDING_API__H
#define STUN_BINDING_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define STUN_BINDING_MAX_CONCURRENT_SESSIONS    10
#define STUN_IP_ADDR_MAX_LEN            46

/******************************************************************************/

typedef enum
{
    STUN_BIND_CLIENT_SESSION = 0,
    STUN_BIND_SERVER_SESSION,
    STUN_BIND_SESSION_TYPE_MAX,
} binding_session_type_t;


typedef int32_t (*stun_binding_session_nwk_send_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, handle app_param);
typedef handle (*stun_binding_session_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*stun_binding_session_stop_timer_cb) (handle timer_id);


typedef struct {
    stun_binding_session_nwk_send_cb nwk_cb;
    stun_binding_session_start_timer_cb start_timer_cb;
    stun_binding_session_stop_timer_cb  stop_timer_cb;
} stun_binding_instance_callbacks_t;


/******************************************************************************/

int32_t stun_binding_create_instance(handle *h_inst);

int32_t stun_binding_instance_set_callbacks(handle h_inst, 
                                stun_binding_instance_callbacks_t *cb);

int32_t stun_binding_destroy_instance(handle h_inst);

int32_t stun_binding_create_session(handle h_inst, 
                binding_session_type_t sess_type, handle *h_session);

int32_t stun_binding_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param);

int32_t stun_binding_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t stun_binding_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t stun_binding_session_set_stun_server(handle h_inst, 
                    handle h_session, stun_inet_addr_type_t stun_srvr_type, 
                    u_char *stun_srvr, uint32_t stun_port);

int32_t stun_binding_destroy_session(handle h_inst, handle h_session);

int32_t stun_binding_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg);

int32_t stun_binding_session_send_message(handle h_inst, 
                            handle h_session, stun_msg_type_t msg_type);

int32_t stun_binding_session_inject_timer_event(
                        handle timer_id, handle arg, handle *bind_session);

int32_t stun_binding_instance_find_session_for_received_msg(
                            handle h_inst, handle h_msg, handle *h_session);

int32_t stun_binding_session_get_xor_mapped_address(handle h_inst, 
                        handle h_session, stun_inet_addr_t *mapped_addr);

int32_t stun_binding_session_get_mapped_address(handle h_inst, 
                        handle h_session, stun_inet_addr_t *mapped_addr);

int32_t stun_binding_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance);

int32_t stun_binding_session_enable_session_refresh(
                handle h_inst, handle h_session, uint32_t duration);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
