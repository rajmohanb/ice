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

#define TURN_PERM_REFRESH_DURATION      300 /** seconds */
#define TURN_KEEP_ALIVE_DURATION        15  /** seconds */

/******************************************************************************/


typedef enum
{
    TURN_CREATE_PERMISSION = 0,
    TURN_CHANNEL_BIND,
} turn_perm_method_t;


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


/** 
 * This callback will be called when the TURN stack wants to 
 * send data over the network to the specified destination.
 */
typedef int32_t (*turn_session_nwk_send_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, handle app_param);

/** 
 * This callback will be called when the TURN stack wants to 
 * pass on the application data (say RTP, RTCP or encoded stun msg)
 * to the TURN application.
 */
typedef void (*turn_session_rx_app_data) (handle h_inst, 
                        handle h_turn_session, void *data, uint32_t data_len, 
                        stun_inet_addr_t *src, handle transport_param);

/** 
 * This callback will be called when the TURN stack wants to 
 * start a timer. The duration is specified in milliseconds and
 * the argument that needs to be passed by the application in
 * case the timer expires. The application is expected to 
 * return a valid timer handle that can be subsequently used to
 * identify the specific instance of the timer.
 */
typedef handle (*turn_session_start_timer_cb) (uint32_t duration, handle arg);


/** 
 * This callback will be called when the TURN stack wants to 
 * stop a timer. The timer to be stopped is indicated by the
 * timer_id.
 */
typedef int32_t (*turn_session_stop_timer_cb) (handle timer_id);


/** 
 * This callback will be called when the TURN stack wants to notify
 * the application about the change in the state of the session.
 */
typedef void (*turn_session_state_change_cb) (handle h_nist, 
                        handle h_session, turn_session_state_t state);


typedef struct {
    turn_session_nwk_send_cb nwk_cb;
    turn_session_rx_app_data rx_data_cb;
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

int32_t turn_clear_session(handle h_inst, handle h_session);

int32_t turn_session_inject_received_msg(
                        handle h_inst, handle h_session, handle h_msg);

int32_t turn_session_allocate(handle h_inst, handle h_session);

int32_t turn_session_create_permissions(handle h_inst, 
                            handle h_session, turn_perm_method_t method);

int32_t turn_session_bind_channel(handle h_inst, 
                        handle h_session, stun_inet_addr_t *peer);

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

int32_t turn_session_get_application_data(handle h_inst,
                                handle h_session, stun_inet_addr_t *peer_src,
                                u_char *data, uint32_t len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
