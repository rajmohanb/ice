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

#ifndef ICE_INT__H
#define ICE_INT__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


typedef struct {
    handle h_inst;
    handle h_session;
} ice_int_params_t;


typedef struct {
    handle h_media;
    uint32_t comp_id;
    uint32_t len;
    u_char *data;
} ice_media_data_t;


typedef enum {
    ICE_TURN_TIMER = 0,     /** timer type for turn */
    ICE_BIND_TIMER,         /** timer type for stun binding */
    ICE_CC_TIMER,           /** timer type for conn check module */
    ICE_CHECK_LIST_TIMER,   /** checklist timer */
    ICE_NOMINATION_TIMER,   /** nomination timer */
    ICE_KEEP_ALIVE_TIMER,   /** keep alive timer for refreshing nat bindings */
    
    /** that's all we have as of now ... */
} ice_timer_type_t;


typedef struct {
    handle h_instance; /** ice instance */
    handle h_session;  /** ice session */
    handle h_media;    /** ice media */
    ice_timer_type_t type;
    handle timer_id;
    handle arg;
} ice_timer_params_t;


typedef enum
{
    ICE_AGENT_ROLE_CONTROLLING,
    ICE_AGENT_ROLE_CONTROLLED,
    ICE_AGENT_ROLE_TYPE_MAX,
} ice_agent_role_type_t;


typedef enum
{
    ICE_CP_EVENT_UNFREEZE = 0,
    ICE_CP_EVENT_INIT_CHECK,
    ICE_EP_EVENT_CHECK_SUCCESS,
    ICE_CP_EVENT_CHECK_FAILED,
    ICE_CP_EVENT_MAX,
} ice_cp_event_t;


typedef enum
{
    ICE_CP_FROZEN = 0,
    ICE_CP_WAITING,
    ICE_CP_INPROGRESS,
    ICE_CP_SUCCEEDED,
    ICE_CP_FAILED,
    ICE_CP_STATE_MAX,
} ice_cp_state_t;


typedef struct
{
    stun_inet_addr_type_t type;
    u_char ip_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t port;
    stun_transport_protocol_type_t protocol;
} ice_transport_t;


typedef struct tag_ice_candidate
{
    ice_transport_t transport;
    ice_cand_type_t type;

    /** local preference provided by the ICE agent */
    uint32_t local_pref;

    uint32_t priority;
    u_char foundation[ICE_FOUNDATION_MAX_LEN];
    uint32_t comp_id;

    /** related address? */
    struct tag_ice_candidate *base;

    handle transport_param;

    bool_t default_cand;

} ice_candidate_t;


typedef struct
{
    ice_candidate_t *local_cand;

    stun_inet_addr_t peer_addr;

    uint32_t prflx_priority;
    bool_t nominated;
    bool_t controlling_role;

    handle h_transport_conn;

} ice_ic_check_t;


/** Forward declaration */
typedef struct struct_ice_media_stream ice_media_stream_t;

typedef struct
{
    ice_candidate_t *local;
    ice_candidate_t *remote;
    bool_t default_pair;
    bool_t valid_pair;
    bool_t nominated;

    ice_cp_state_t state;

    /** pair priority */
    uint64_t priority;

    /** whether the check is to be nominated or not */
    bool_t check_nom_status;

    handle h_cc_session;
    handle h_cc_cancel;

    handle h_transport_conn;

    /** parent */
    ice_media_stream_t *media;

} ice_cand_pair_t;



typedef enum 
{
    ICE_INIT_GATHERING = 0,
    ICE_GATHERED_CANDS,
    ICE_GATHER_FAILED,
    ICE_FORM_CHECKLIST,
    ICE_CONN_CHECKS_START,
    ICE_CONN_CHECKS_DONE,
    ICE_MSG,
    ICE_CHECK_LIST_TIMER_EXPIRY,
    ICE_RESTART,
    ICE_REMOTE_PARAMS,
    ICE_ADD_MEDIA,
    ICE_REMOVE_MEDIA,
    ICE_CONN_CHECK_TIMER,
    ICE_NOMINATION_TIMER_EXPIRY,
    ICE_KEEP_ALIVE_EXPIRY,
    ICE_SEND_MEDIA_DATA,
    ICE_SES_EVENT_MAX,
} ice_session_event_t;


typedef enum
{
    ICE_SES_IDLE = 0,
    ICE_SES_GATHERING,
    ICE_SES_GATHERED,
    ICE_SES_CC_RUNNING,
    ICE_SES_CC_COMPLETED,
    ICE_SES_CC_FAILED,
    ICE_SES_NOMINATING,
    ICE_SES_ACTIVE,
    ICE_SES_STATE_MAX,
} ice_session_state_t;


typedef enum
{
    ICE_MEDIA_GATHER = 0,
    ICE_MEDIA_RELAY_MSG,
    ICE_MEDIA_GATHER_RESP,
    ICE_MEDIA_GATHER_FAILED,
    ICE_MEDIA_FORM_CHECKLIST,
    ICE_MEDIA_UNFREEZE,
    ICE_MEDIA_CHECKLIST_TIMER,
    ICE_MEDIA_CC_MSG,
    ICE_MEDIA_RESTART,
    ICE_MEDIA_REMOTE_PARAMS,
    ICE_MEDIA_BOTH_LITE,
    ICE_MEDIA_CC_TIMER,
    ICE_MEDIA_NOMINATION_TIMER,
    ICE_MEDIA_KEEP_ALIVE_TIMER,
    ICE_MEDIA_SEND_DATA,
    ICE_MEDIA_EVENT_MAX,
} ice_media_stream_event_t;

typedef enum
{
    ICE_MEDIA_IDLE = 0,
    ICE_MEDIA_GATHERING,
    ICE_MEDIA_GATHERED,
    ICE_MEDIA_FROZEN,
    ICE_MEDIA_CC_RUNNING,
    ICE_MEDIA_NOMINATING,
    ICE_MEDIA_CC_COMPLETED,
    ICE_MEDIA_CC_FAILED,
    ICE_MEDIA_STATE_MAX,
} ice_media_stream_state_t;


typedef struct ice_trigger_check_node
{
    ice_cand_pair_t *cp;
    struct ice_trigger_check_node *next;
} ice_trigger_check_node_t;


typedef struct ice_component
{
    uint32_t comp_id;

    /** keep alive timer */
    ice_timer_params_t *keepalive_timer;

    /** handle to the nominated pair */
    ice_cand_pair_t *np;

} ice_component_t;


/** forward declaration */
typedef struct struct_ice_session ice_session_t;

struct struct_ice_media_stream
{
    /** pointer back to the parent ICE session */
    ice_session_t *ice_session; 

    uint32_t num_comp;
    uint32_t num_comp_gathered;

    /** count of peer components */
    uint32_t num_peer_comp;

    char local_ufrag[ICE_MAX_UFRAG_LEN];
    char local_pwd[ICE_MAX_PWD_LEN];

    char peer_ufrag[ICE_MAX_UFRAG_LEN];
    char peer_pwd[ICE_MAX_PWD_LEN];

    /** media stream state - encompasses check list state as well */
    ice_media_stream_state_t state;

    /** check list timer used during connectivity checks */
    ice_timer_params_t *checklist_timer;

    /** connectivity checks valid pair evaluation timer */
    ice_timer_params_t *nomination_timer;

    /** check list */
    uint32_t num_cand_pairs;
    ice_cand_pair_t ah_cand_pairs[ICE_MAX_CANDIDATE_PAIRS];

    /** previous selected pairs, used during media restart */
    ice_cand_pair_t ah_prev_sel_pair[ICE_MAX_COMPONENTS];

    ice_candidate_t as_local_cands[ICE_CANDIDATES_MAX_SIZE];
    ice_candidate_t as_remote_cands[ICE_CANDIDATES_MAX_SIZE];

    /** triggered FIFO check queue */
    ice_trigger_check_node_t *trig_check_list;

    /** 
     * list that stores incoming conn check pair details 
     * when answer is not yet received from remote 
     */
    uint32_t ic_check_count;
    ice_ic_check_t ic_checks[ICE_MAX_CANDIDATE_PAIRS];

    handle h_turn_sessions[ICE_MAX_COMPONENTS];
    handle h_bind_sessions[ICE_MAX_COMPONENTS];
    handle h_cc_svr_session;
 
    ice_component_t media_comps[ICE_MAX_COMPONENTS];

    bool_t o_removed;
};



typedef struct 
{
    /** turn instance handle */
    handle h_turn_inst;

    /** stun binding instance handle */
    handle h_bind_inst;

    /** software client name and version */
    uint32_t client_name_len;
    u_char *client_name;

    /** session list */
    handle  h_table;

    /** connectivity check module instance handle */
    handle h_cc_inst;

    /** agent application platform callbacks */
    ice_session_nwk_send_cb nwk_send_cb;
    ice_session_start_timer_cb start_timer_cb;
    ice_session_stop_timer_cb stop_timer_cb;
    ice_session_rx_app_data rx_app_data_cb;

    /** ice nomination mode */
    ice_nomination_type_t nomination_mode;

    /** 
     * agent application event handler callbacks 
     * for notification of change in states.
     */
    ice_session_state_change_event_cb session_state_event_cb;
    ice_media_state_change_event_cb media_state_event_cb;

    handle *aps_sessions[ICE_MAX_CONCURRENT_SESSIONS];

} ice_instance_t;


struct struct_ice_session
{
    ice_instance_t *instance;
    ice_session_state_t state;

    ice_mode_type_t local_mode;
    ice_mode_type_t peer_mode;

    /** controlling or controlled */
    ice_agent_role_type_t role;

    /** tie-breaker */
    uint64_t tie_breaker;

    uint32_t num_media_streams;
    ice_media_stream_t *aps_media_streams[ICE_MAX_MEDIA_STREAMS];

    bool_t use_relay;
    bool_t o_destroyed;

    /**
     * turn/relay server configuration
     */
    ice_relay_server_cfg_t turn_cfg;

    /**
     * stun server configuration
     */
    ice_stun_server_cfg_t stun_cfg;
};


typedef int32_t (*ice_session_fsm_handler) 
                    (ice_session_t *session, handle h_msg, handle *h_param);
typedef int32_t (*ice_media_stream_fsm_handler)
                    (ice_media_stream_t *media, handle h_msg);
typedef int32_t (*ice_cand_pair_fsm_handler)
                    (ice_cand_pair_t *cp, handle h_msg);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
