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

#ifndef TURN_API__H
#define TURN_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define TURN_SVR_IP_ADDR_MAX_LEN        16
#define TURN_SERVER_DEFAULT_PORT        3478
#define TURN_MAX_USERNAME_LEN           128
#define TURN_MAX_PASSWORD_LEN           128
#define TURN_MAX_REALM_LEN              64
#define TURN_MAX_CONCURRENT_SESSIONS    10
#define TURN_MAX_PERMISSIONS            3

/******************************************************************************/


typedef enum 
{
    TURN_IDLE = 0,
    TURN_OG_ALLOCATING,
    TURN_OG_ALLOCATED,
    TURN_OG_CREATING_PERM,
    TURN_OG_ACTIVE,
    TURN_OG_DEALLOCATING,
    TURN_OG_FAILED,
    TURN_STATE_MAX,
} turn_session_state_t;


typedef int32_t (*turn_session_nwk_send_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, handle app_param);
typedef handle (*turn_session_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*turn_session_stop_timer_cb) (handle timer_id);
typedef void (*turn_session_state_change_cb) (handle h_nist, 
                        handle h_session, turn_session_state_t state);


typedef struct {
    turn_session_nwk_send_cb nwk_cb;
    turn_session_start_timer_cb start_timer_cb;
    turn_session_stop_timer_cb  stop_timer_cb;
    turn_session_state_change_cb session_state_cb;
} turn_instance_callbacks_t;


typedef struct {

    /** 
     * relay server address and port 
     */
    stun_inet_addr_t    server;

    /**
     * username if relay server requires authentication.
     */
    u_char              username[TURN_MAX_USERNAME_LEN];

    /**
     * credentials if relay server requires authentication.
     */
    u_char              credential[TURN_MAX_PASSWORD_LEN];

    /**
     * realm if relay server requires authentication
     */
    u_char              realm[TURN_MAX_REALM_LEN];

} turn_server_cfg_t;


/**
 * This data structure is passed on to application when the 
 * turn session fsm state changes to TURN_OG_ALLOCATED.
 */
typedef struct
{
    /** relayed transport address */
    stun_inet_addr_t relay_addr;

    /** server reflexive transport address */
    stun_inet_addr_t mapped_addr;

    /** expiry time */
    uint32_t lifetime;

} turn_session_alloc_info_t;


/******************************************************************************/

int32_t turn_create_instance(handle *h_inst);

int32_t turn_instance_set_callbacks(handle h_inst, 
                                        turn_instance_callbacks_t *cb);

int32_t turn_instance_set_client_software_name(handle h_inst, 
                                                u_char *client, uint32_t len);

int32_t turn_destroy_instance(handle h_inst);



int32_t turn_create_session(handle h_inst, handle *h_session);

int32_t turn_session_set_relay_server_cfg(handle h_inst, 
                            handle h_session, turn_server_cfg_t *server);

int32_t turn_session_set_app_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t turn_session_get_app_param(handle h_inst, 
                                    handle h_session, handle *h_param);

int32_t turn_session_set_transport_param(handle h_inst, 
                                    handle h_session, handle h_param);

int32_t turn_destroy_session(handle h_inst, handle h_session);

int32_t turn_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg);

int32_t turn_session_send_message(handle h_inst, 
                            handle h_session, stun_method_type_t method, 
                            stun_msg_type_t msg_type);

int32_t turn_instance_find_session_for_received_msg(handle h_inst, 
                                        handle h_msg, handle *h_session);

int32_t turn_session_inject_timer_message(handle h_timerid, handle h_timer_arg);

int32_t turn_session_timer_get_session_handle (
                    handle arg, handle *h_session, handle *h_instance);

int32_t turn_session_get_allocation_info(handle h_inst, 
                        handle h_session, turn_session_alloc_info_t *info);

int32_t turn_session_add_peer_address(handle h_inst, 
                                    handle h_session, stun_inet_addr_t *addr);

int32_t turn_session_send_application_data(handle h_inst, 
                            handle h_session, stun_inet_addr_t *peer_dest,
                            u_char *data, uint32_t len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
