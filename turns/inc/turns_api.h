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

#ifndef TURNS_API__H
#define TURNS_API__H

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

#define TURNS_MAX_PERMISSIONS           5

#define TURNS_PERM_REFRESH_DURATION     300 /** seconds */

#define TURNS_CHANNEL_BINDING_DURATION  600 /** seconds */

#define TURN_KEEP_ALIVE_DURATION        15  /** seconds */

#define TURNS_SERVER_NONCE_LEN          64

#define TURNS_MMAP_FILE_PATH            "/tmp/mbiceserver"

#define TURNS_ERROR_REASON_LENGTH       256

#define TURNS_PORT_RANGE_MIN            49152

#define TURNS_PORT_RANGE_MAX            65535

#define TURNS_ALLOCATION_NONCE_STALE_TIMER  3600    /** seconds */

#define TURNS_CHANNEL_NUMBER_MIN        0x4000
#define TURNS_CHANNEL_NUMBER_MAX        0x7FFE


/******************************************************************************/



typedef enum
{
    TURNS_EV_DEALLOCATED,
    TURNS_EV_BANDWIDTH,
} turns_event_t;



/** source and destination transport details about the received stun msg */
typedef struct
{
    /** parsed stun packet handle */
    handle h_msg;

    /** transport parameter */
    handle transport_param;
    //stun_inet_addr_t local_intf;

    /** source address of stun packet */
    stun_inet_addr_t src;

    /** the transport protocol */
    stun_transport_protocol_type_t protocol;

    stun_inet_addr_t local_intf;

} turns_rx_stun_pkt_t;




/** source and destination transport details about the received channel data */
typedef struct
{
    /** received data and data length */
    u_char *data;
    uint32_t data_len;

    /** transport parameter */
    handle transport_param;

    /** source address of stun packet */
    stun_inet_addr_t src;

    /** the transport protocol */
    stun_transport_protocol_type_t protocol;

} turns_rx_channel_data_t;




/** 
 * when new allocation request is received, this data structure provides all 
 * the details about the new allocation request which will aid the application 
 * in determining whether to approve the allocation request or deny it.
 */
typedef struct
{
    u_char *username;
    uint32_t username_len;
    u_char *realm;
    uint32_t realm_len;
    uint32_t lifetime;
    stun_transport_protocol_type_t protocol;
    void   *blob;
} turns_new_allocation_params_t;



typedef struct
{
    handle blob;
    bool_t approved;
    uint32_t lifetime; /** in secs, if approved */
    uint32_t code;
    char reason[TURNS_ERROR_REASON_LENGTH];
    char key[16];
} turns_allocation_decision_t;


/******************************************************************************/


/** 
 * This callback will be called when the TURN stack wants the
 * application to listen for data on  a new socket.
 */
typedef int32_t (*turns_new_socket_cb) (handle h_alloc, int sock_id);


/** 
 * This callback will be called when the TURN stack wants to 
 * send data over the network to the specified destination.
 */
typedef int32_t (*turns_nwk_send_data_cb) (u_char *data, 
        uint32_t data_len, stun_inet_addr_type_t ip_addr_type, 
        u_char *ip_addr, uint32_t port, handle transport_param, u_char *key);


/** 
 * This callback will be called when the TURN stack wants to 
 * send data over the network to the specified destination.
 */
typedef int32_t (*turns_nwk_send_stun_msg_cb) (handle h_msg, 
                    stun_inet_addr_type_t ip_addr_type, u_char *ip_addr, 
                    uint32_t port, handle transport_param, u_char *key);


/** 
 * This callback will be called when the TURN stack wants to 
 * start a timer. The duration is specified in milliseconds and
 * the argument that needs to be passed by the application in
 * case the timer expires. The application is expected to 
 * return a valid timer handle that can be subsequently used to
 * identify the specific instance of the timer.
 */
typedef handle (*turns_start_timer_cb) (uint32_t duration, handle arg);


/** 
 * This callback will be called when the TURN stack wants to 
 * stop a timer. The timer to be stopped is indicated by the
 * timer_id.
 */
typedef int32_t (*turns_stop_timer_cb) (handle timer_id);


typedef struct {
    turns_nwk_send_data_cb nwk_data_cb;
    turns_nwk_send_stun_msg_cb nwk_stun_cb;
    turns_new_socket_cb new_socket_cb;
    turns_start_timer_cb start_timer_cb;
    turns_stop_timer_cb  stop_timer_cb;
} turns_osa_callbacks_t;



/** 
 * This callback will be called when the TURNS stack wants to notify the 
 * server application about the reception of a new allocation request. The 
 * server application must not perform any intensive operations within 
 * this callback.
 */
typedef int32_t (*turns_new_alloc_cb) (
            handle h_alloc, turns_new_allocation_params_t *params);


/** 
 * This callback will be called when the TURNS stack wants to notify the 
 * server application about an event for an existing allocation. The server 
 * application must not perform any intensive operations within this callback.
 */
typedef int32_t (*turns_alloc_event_cb) (turns_event_t event, handle h_alloc);



typedef struct {
    turns_new_alloc_cb      new_alloc_cb;
    turns_alloc_event_cb    alloc_event_cb;
} turns_event_callbacks_t;



/******************************************************************************/



int32_t turns_create_instance(uint32_t max_allocs, 
                        uint32_t num_media_procs, handle *h_inst);


int32_t turns_instance_set_osa_callbacks(
                        handle h_inst, turns_osa_callbacks_t *cb);


int32_t turns_instance_set_event_callbacks(
                        handle h_inst, turns_event_callbacks_t *event_cbs);


int32_t turns_instance_set_server_software_name(
                        handle h_inst, char *client, uint32_t len);


int32_t turns_instance_set_realm(handle h_inst, char *realm, uint32_t len);


int32_t turns_instance_set_nonce_stale_timer_value(
                                handle h_inst, uint32_t timeout);


int32_t turns_destroy_instance(handle h_inst);



int32_t turns_inject_received_msg(handle h_inst, turns_rx_stun_pkt_t *stun_pkt);



int32_t turns_inject_received_channeldata_msg(
                handle h_inst, turns_rx_channel_data_t *chnl_data);


int32_t turns_inject_timer_event(handle timer_id, handle arg);


int32_t turns_verify_valid_stun_packet(u_char *pkt, uint32_t pkt_len);



int32_t turns_inject_allocation_decision(
            handle h_inst, turns_allocation_decision_t *decision);


int32_t turns_inject_received_udp_msg(
                handle h_inst, turns_rx_channel_data_t *chnl_data);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
