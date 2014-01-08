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

#ifndef STUNS_API__H
#define STUNS_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define STUNS_MAX_CONCURRENT_SESSIONS    100

#define TURN_SVR_IP_ADDR_MAX_LEN        16
#define TURN_SERVER_DEFAULT_PORT        3478
#define TURN_MAX_USERNAME_LEN           128
#define TURN_MAX_PASSWORD_LEN           128
#define TURN_MAX_REALM_LEN              64
#define TURN_MAX_PERMISSIONS            3

#define TURN_PERM_REFRESH_DURATION      300 /** seconds */
#define TURN_KEEP_ALIVE_DURATION        15  /** seconds */

#define TURNS_SERVER_NONCE_LEN          64

/******************************************************************************/



/** source and destination transport details about the received stun msg */
typedef struct
{
    /** parsed stun packet handle */
    handle h_msg;

    /** transport parameter */
    handle transport_param;

    /** source address of stun packet */
    stun_inet_addr_t src;

    /** the transport protocol */
    stun_transport_protocol_type_t protocol;

} stuns_rx_stun_pkt_t;



/******************************************************************************/


/** 
 * This callback will be called when the STUNS stack wants to 
 * send data over the network to the specified destination.
 */
typedef int32_t (*stuns_nwk_send_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, u_char *key);

/** 
 * This callback will be called when the STUNS stack wants to 
 * start a timer. The duration is specified in milliseconds and
 * the argument that needs to be passed by the application in
 * case the timer expires. The application is expected to 
 * return a valid timer handle that can be subsequently used to
 * identify the specific instance of the timer.
 */
typedef handle (*stuns_start_timer_cb) (uint32_t duration, handle arg);


/** 
 * This callback will be called when the STUNS stack wants to 
 * stop a timer. The timer to be stopped is indicated by the
 * timer_id.
 */
typedef int32_t (*stuns_stop_timer_cb) (handle timer_id);


typedef struct {
    stuns_nwk_send_cb nwk_cb;
    stuns_start_timer_cb start_timer_cb;
    stuns_stop_timer_cb  stop_timer_cb;
} stuns_osa_callbacks_t;


/******************************************************************************/


int32_t stuns_create_instance(handle *h_inst);



int32_t stuns_instance_set_osa_callbacks(
                        handle h_inst, stuns_osa_callbacks_t *cb);


int32_t stuns_instance_set_server_software_name(
                        handle h_inst, char *client, uint32_t len);


int32_t stuns_destroy_instance(handle h_inst);


int32_t stuns_inject_received_msg(handle h_inst, stuns_rx_stun_pkt_t *stun_pkt);


int32_t stuns_inject_timer_event(
                    handle timer_id, handle arg, handle *ice_session);


int32_t stuns_verify_valid_stun_packet(u_char *pkt, uint32_t pkt_len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
