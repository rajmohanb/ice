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

#ifndef ICE_API__H
#define ICE_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include "ice_cfg.h"


typedef enum
{
    ICE_GATHERED,
    ICE_CC_RUNNING,
    ICE_CC_COMPLETED,
    ICE_CC_FAILED,
    ICE_STATE_MAX,
} ice_state_t;


typedef enum {
    ICE_TRANSPORT_UDP = 0,
    ICE_TRANSPORT_TCP,
} ice_transport_type_t;


typedef enum
{
    INVALID_CAND_TYPE = 0,
    HOST_CANDIDATE,
    SERVER_REFLEXIVE_CANDIDATE,
    RELAYED_CANDIDATE,
    PEER_REFLEXIVE_CANDIDATE,
} ice_cand_type_t;


typedef enum
{
    ICE_SESSION_OUTGOING = 0,
    ICE_SESSION_INCOMING,
} ice_session_type_t;


typedef enum
{
    ICE_MODE_LITE = 0,
    ICE_MODE_FULL,
    ICE_INVALID_MODE,
} ice_mode_type_t;


/** source and destination transport details about the received stun msg */
typedef struct
{
    /** parsed stun packet handle */
    handle h_msg;

    /** transport parameter */
    handle transport_param;

    /** source address of stun packet */
    stun_inet_addr_t src;

} ice_rx_stun_pkt_t;


typedef int32_t (*ice_session_nwk_send_cb) (u_char *buf, 
            uint32_t buf_len, u_char *ip_addr, uint32_t port, handle param);
typedef handle (*ice_session_start_timer_cb) (uint32_t duration, handle arg);
typedef int32_t (*ice_session_stop_timer_cb) (handle timer_id);


typedef struct {
    ice_session_nwk_send_cb nwk_cb;
    ice_session_start_timer_cb start_timer_cb;
    ice_session_stop_timer_cb  stop_timer_cb;
} ice_instance_callbacks_t;


typedef void (*ice_session_state_change_event_cb) (handle h_inst, 
                                        handle h_session, ice_state_t state);
typedef void (*ice_media_state_change_event_cb) (handle h_inst, 
                        handle h_session, handle h_media, ice_state_t state);

typedef struct {
    ice_session_state_change_event_cb session_state_cb;
    ice_media_state_change_event_cb media_state_cb;
} ice_state_event_handlers_t;


typedef struct {

    /** 
     * stun server details
     */
    stun_inet_addr_t      server;

} ice_stun_server_cfg_t;


typedef struct {

    /** 
     * relay server address and port 
     */
    stun_inet_addr_t      server;

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

} ice_relay_server_cfg_t;


typedef struct {
    char ice_ufrag[ICE_MAX_UFRAG_LEN];
    char ice_pwd[ICE_MAX_PWD_LEN];
} ice_media_credentials_t;


typedef struct
{
    /** host candidate transport details */
    stun_inet_addr_type_t type;
    u_char ip_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t port;
    ice_transport_type_t protocol;

    /** component id */
    uint32_t comp_id;

    /** application transport handle */
    handle transport_param;

} ice_media_host_comp_t;


typedef struct
{
    /** 
     * number of media components associated with this media stream
     */
    uint32_t num_comp;

    /**
     * ice user name fragment and password
     */
    char ice_ufrag[ICE_MAX_UFRAG_LEN];
    char ice_pwd[ICE_MAX_PWD_LEN];

    /**
     * component details for this media stream
     */
    ice_media_host_comp_t host_cands[ICE_MAX_COMPONENTS];

} ice_api_media_stream_t;


typedef struct
{
    u_char foundation[ICE_FOUNDATION_MAX_LEN];
    uint32_t component_id;
    ice_transport_type_t protocol;
    uint64_t priority;
    u_char ip_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t port;
    ice_cand_type_t cand_type;
    u_char rel_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t rel_port;
} ice_cand_params_t;


typedef struct
{
    uint32_t comp_id;

    /** default destination - m & c lines of SDP */
    stun_inet_addr_t default_dest;
   
    /** correspond to SDP a=candidate ice attributes */
    uint32_t num_cands;
    ice_cand_params_t cands[ICE_MAX_GATHERED_CANDS];

    /** corresponds to SDP remote-candidate media attribute */
    uint32_t num_remote_cands;
    stun_inet_addr_t remote_cands[ICE_MAX_GATHERED_CANDS];
} ice_media_comp_t;


typedef struct
{
    handle h_media;
    ice_state_t media_state;

    char ice_ufrag[ICE_MAX_UFRAG_LEN];
    char ice_pwd[ICE_MAX_PWD_LEN];

    uint32_t num_comps;
    ice_media_comp_t comps[ICE_MAX_COMPONENTS];
} ice_media_params_t;


typedef struct
{
    /** ice mode */
    ice_mode_type_t ice_mode;

    uint32_t num_media;
    ice_media_params_t media[ICE_MAX_MEDIA_STREAMS];
} ice_session_params_t;


typedef struct
{
    uint32_t comp_id;
    stun_inet_addr_t local;
    stun_inet_addr_t peer;
    bool_t nominated;
} ice_valid_pair_t;


typedef struct
{
    handle h_media;
    uint32_t num_valid;
    ice_valid_pair_t pairs[ICE_MAX_VALID_LIST_PAIRS];
} ice_media_valid_pairs_t;

typedef struct
{
    uint32_t num_media;
    ice_media_valid_pairs_t media_list[ICE_MAX_MEDIA_STREAMS];
} ice_session_valid_pairs_t;


/******************************************************************************/

int32_t ice_create_instance(handle *h_inst);

int32_t ice_instance_set_callbacks(handle h_inst, 
                                        ice_instance_callbacks_t *cbs);

int32_t ice_instance_register_event_handlers(handle h_inst, 
                        ice_state_event_handlers_t *event_handlers);

int32_t ice_set_client_software_name(handle h_inst, u_char *name);

int32_t ice_destroy_instance(handle h_inst);

int32_t ice_instance_verify_valid_stun_packet(void);

int32_t ice_create_session(handle h_inst, 
        ice_session_type_t session_type, ice_mode_type_t mode, handle *h_session);

int32_t ice_session_set_relay_server_cfg(handle h_inst, 
                            handle h_session, ice_relay_server_cfg_t *relay);

int32_t ice_session_set_stun_server_cfg(handle h_inst, 
                                handle h_session, ice_stun_server_cfg_t *stun);

int32_t ice_session_add_media_stream (handle h_inst, handle h_session, 
                        ice_api_media_stream_t *media, handle *h_media);

int32_t ice_session_remove_media_stream (handle h_inst,
                                handle h_session, handle h_media);

int32_t ice_session_gather_candidates(handle h_inst, handle h_session);

int32_t ice_session_get_session_params(handle h_inst, 
                handle h_session, ice_session_params_t *session_params);

int32_t ice_session_get_media_params(handle h_inst, handle h_session, 
                        handle h_media, ice_media_params_t *media_params);

int32_t ice_session_set_peer_ice_mode(handle h_inst, 
                    handle h_session, ice_mode_type_t remote_ice_mode);

int32_t ice_session_set_peer_session_params(handle h_inst, 
                handle h_session, ice_session_params_t *session_params);

int32_t ice_session_set_remote_ice_mode(handle h_inst, 
                    handle h_session, ice_mode_type_t remote_ice_mode);

int32_t ice_destroy_session(handle h_inst, handle h_session);

int32_t ice_session_inject_received_msg(handle h_inst, 
                            handle h_session, ice_rx_stun_pkt_t *stun_pkt);

int32_t ice_session_form_check_lists(handle h_inst, handle h_session);

int32_t ice_session_start_connectivity_checks(handle h_inst, handle h_session);

int32_t ice_session_inject_timer_event(handle timer_id, handle arg);

int32_t ice_instance_find_session_for_received_msg(handle h_inst, 
                    handle h_msg, handle transport_param, handle *h_session);

int32_t ice_session_get_session_valid_pairs(handle h_inst, 
            handle h_session, ice_session_valid_pairs_t *valid_pairs);

int32_t ice_session_get_media_valid_pairs(handle h_inst, handle h_session, 
                handle h_media, ice_media_valid_pairs_t *valid_pairs);

int32_t ice_session_restart_media_stream (handle h_inst,
                                handle h_session, handle h_media);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
