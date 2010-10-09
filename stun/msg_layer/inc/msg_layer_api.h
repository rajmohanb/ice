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

#ifndef MSG_LAYER_API__H
#define MSG_LAYER_API__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"


#define MAX_STUN_ATTRIBUTES         12

#define MAX_MAPPED_ADDRESS_LEN      46

#define MAX_USERNAME_LEN            513

#define STUN_EXT_ATTR_VALUE_LEN     100

#define MAX_UNKNOWN_ATTRIBUTE_TYPES 4


typedef enum {
    STUN_METHOD_MIN = 0x000,
    STUN_METHOD_BINDING = 0x001,
#ifdef ENABLE_TURN
    STUN_METHOD_ALLOCATE = 0x003,
    STUN_METHOD_REFRESH = 0x004,
    STUN_METHOD_SEND = 0x006,
    STUN_METHOD_DATA = 0x007,
    STUN_METHOD_CREATE_PERMISSION = 0x008,
    STUN_METHOD_CHANNEL_BIND = 0x009,
#endif
    STUN_METHOD_MAX
} stun_method_type_t;


typedef enum {
    STUN_REQUEST = 0,
    STUN_INDICATION,
    STUN_SUCCESS_RESP,
    STUN_ERROR_RESP,
    STUN_MSG_TYPE_MAX
} stun_msg_type_t;


typedef enum {
    STUN_ATTR_MIN = 0x0000,
    STUN_ATTR_MAPPED_ADDR = 0x0001,
    STUN_ATTR_USERNAME = 0x0006,
    STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTR_ERROR_CODE = 0x0009,
    STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x00A,
#ifdef ENABLE_TURN
    STUN_ATTR_CHANNEL_NUMBER = 0x000C,
    STUN_ATTR_LIFETIME = 0x000D,
    STUN_ATTR_XOR_PEER_ADDR = 0x0012,
    STUN_ATTR_DATA = 0x0013,
#endif
    STUN_ATTR_REALM = 0x0014,
    STUN_ATTR_NONCE = 0x0015,
#ifdef ENABLE_TURN
    STUN_ATTR_XOR_RELAYED_ADDR= 0x0016,
    STUN_ATTR_EVEN_PORT = 0x0018,
    STUN_ATTR_REQUESTED_TRANSPORT = 0x0019,
    STUN_ATTR_DONT_FRAGMENT = 0x001A,
#endif
    STUN_ATTR_XOR_MAPPED_ADDR = 0x0020,
#ifdef ENABLE_TURN
    STUN_ATTR_RESERVATION_TOKEN = 0x0022,
#endif
#ifdef ENABLE_ICE
    STUN_ATTR_PRIORITY = 0x0024,
    STUN_ATTR_USE_CANDIDATE = 0x0025,
#endif
    STUN_ATTR_SOFTWARE = 0x8022,
    STUN_ATTR_ALTERNATE_SERVER = 0x8023,
    STUN_ATTR_FINGERPRINT = 0x8028,
#ifdef ENABLE_ICE
    STUN_ATTR_ICE_CONTROLLED = 0x8029,
    STUN_ATTR_ICE_CONTROLLING = 0x802A,
#endif
    STUN_ATTR_UNKNOWN_COMP_OPTIONAL,
    STUN_ATTR_UNKNOWN_COMP_REQUIRED,
    STUN_ATTR_MAX
} stun_attribute_type_t;



typedef enum {
    STUN_ADDR_FAMLY_INVALID = 0x00,
    STUN_ADDR_FAMILY_IPV4 = 0x01,
    STUN_ADDR_FAMILY_IPV6,
} stun_addr_family_type_t;


typedef enum {
    STUN_TRANSPORT_TCP = 6,
    STUN_TRANSPORT_UDP = 17,
    STUN_TRANSPORT_SCTP = 132,
    STUN_TRANSPORT_MAX,
} stun_transport_protocol_type_t;


/** list of stun error codes reason phrase */
#define STUN_ERROR_TRY_ALTERNATE 300
#define STUN_ERROR_BAD_REQUEST   400
#define STUN_ERROR_UNAUTHORIZED  401
#define STUN_ERROR_UNKNOWN_ATTR  420
#define STUN_ERROR_STALE_NONCE   438
#define STUN_ERROR_ROLE_CONFLICT 487
#define STUN_ERROR_SERVER_ERROR  500


/** list of stun error codes reason phrase */
#define STUN_REJECT_RESPONSE_300 "Try Alternate"
#define STUN_REJECT_RESPONSE_400 "Bad Request"
#define STUN_REJECT_RESPONSE_401 "Unauthorized"
#define STUN_REJECT_RESPONSE_420 "Unknown Attribute"
#define STUN_REJECT_RESPONSE_438 "Stale Nonce"
#define STUN_REJECT_RESPONSE_487 "Role Conflict"
#define STUN_REJECT_RESPONSE_500 "Server Error"


/** instance specific apis */
int32_t stun_msg_layer_create_instance(handle *h_instance);

int32_t stun_msg_instance_set_mtu(handle h_instance, uint32_t mtu);

int32_t stun_msg_layer_destroy_instance(handle h_instance);



/* msg specific apis */
int32_t stun_msg_create(stun_msg_type_t msg_type, 
                            stun_method_type_t method_type, handle *h_msg);

int32_t stun_msg_destroy(handle h_msg);

int32_t stun_msg_add_attribute(handle h_msg, handle h_attr);

int32_t stun_msg_remove_attribute(handle h_msg, handle h_attr);

int32_t stun_msg_add_attributes(handle h_msg, handle *ah_attr, uint32_t num);

int32_t stun_msg_get_method(handle h_msg, stun_method_type_t *method);

int32_t stun_msg_get_class(handle h_msg, stun_msg_type_t *class_type);

int32_t stun_msg_get_txn_id(handle h_msg, u_char *txn_id);

int32_t stun_msg_set_txn_id(handle h_msg, u_char *txn_id);

int32_t stun_msg_get_num_attributes(handle h_msg, uint32_t *num);

int32_t stun_msg_get_specified_attributes(handle h_msg, 
        stun_attribute_type_t attr_type, handle *pah_attr, uint32_t *size);

int32_t stun_msg_create_resp_from_req(handle h_req,
                            stun_msg_type_t msg_type, handle *h_resp);

int32_t stun_msg_validate_message_integrity(
                            handle h_msg, u_char *key, uint32_t key_len);

int32_t stun_msg_validate_fingerprint(handle h_msg);


/* ========================================================================== */

/** generic attribute apis */
int32_t stun_attr_create(stun_attribute_type_t attr_type, handle *h_attr);

int32_t stun_attr_destroy(handle h_attr);


/* ========================================================================== */

/** attribute specific apis */
int32_t stun_attr_software_set_value(handle h_attr, 
                                            u_char *value, uint16_t len);

int32_t stun_attr_software_get_value_length(handle h_attr, uint32_t *len);

int32_t stun_attr_software_get_value(handle h_attr, 
                                        u_char *value, uint16_t *len);

/* ========================================================================== */

int32_t stun_attr_mapped_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len);

int32_t stun_attr_mapped_addr_get_port(handle h_attr, uint32_t *port);

/* ========================================================================== */

int32_t stun_attr_xor_mapped_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len);

int32_t stun_attr_xor_mapped_addr_set_address(handle h_attr, 
            u_char *address, uint32_t len, stun_addr_family_type_t family);

int32_t stun_attr_xor_mapped_addr_get_port(handle h_attr, uint32_t *port);

int32_t stun_attr_xor_mapped_addr_set_port(handle h_attr, uint32_t port);

/* ========================================================================== */

int32_t stun_attr_xor_relayed_addr_get_address(handle h_attr, 
        stun_addr_family_type_t *addr_family, u_char *address, uint32_t *len);

int32_t stun_attr_xor_relayed_addr_get_port(handle h_attr, uint32_t *port);

/* ========================================================================== */

int32_t stun_attr_xor_peer_addr_get_address(handle h_attr, 
                                    u_char *address, uint32_t *len);

int32_t stun_attr_xor_peer_addr_get_port(handle h_attr, uint32_t *port);

/* ========================================================================== */

int32_t stun_attr_lifetime_get_duration(handle h_attr, uint32_t *duration);

int32_t stun_attr_lifetime_set_duration(handle h_attr, uint32_t duration);

/* ========================================================================== */

int32_t stun_attr_error_code_get_error_code(handle h_attr, uint32_t *error_code);

int32_t stun_attr_error_code_set_error_code(handle h_attr, uint32_t code);

int32_t stun_attr_error_code_set_error_reason(
                            handle h_attr, char *reason, uint32_t len);

/* ========================================================================== */

int32_t stun_attr_username_get_username_length(handle h_attr, uint32_t *len);

int32_t stun_attr_username_get_username(handle h_attr, 
                                            u_char *name, uint32_t *len);

int32_t stun_attr_username_set_username(handle h_attr, 
                                            u_char *name, uint32_t len);

/* ========================================================================== */

int32_t stun_attr_realm_get_realm_length(handle h_attr, uint32_t *len);

int32_t stun_attr_realm_get_realm(
                            handle h_attr, u_char *realm_val, uint32_t *len);
int32_t stun_attr_realm_set_realm(
                            handle h_attr, u_char *realm_val, uint32_t len);

/* ========================================================================== */

int32_t stun_attr_unknown_attributes_add_attr_type(
                                        handle h_attr, uint16_t attr_type);

/* ========================================================================== */

int32_t stun_attr_nonce_set_nonce(
                            handle h_attr, u_char *nonce_val, uint32_t len);

int32_t stun_attr_nonce_get_nonce_length(handle h_attr, uint32_t *len);

int32_t stun_attr_nonce_get_nonce(
                            handle h_attr, u_char *nonce_val, uint32_t *len);

/* ========================================================================== */

int32_t stun_attr_requested_transport_set_protocol(
                        handle h_attr, stun_transport_protocol_type_t proto);

/* ========================================================================== */


int32_t stun_attr_priority_get_priority(handle h_attr, uint32_t *priority);

int32_t stun_attr_priority_set_priority(handle h_attr, uint32_t priority);

int32_t stun_attr_ice_controlling_get_tiebreaker_value(
                                            handle h_attr, uint64_t *tiebreak);

int32_t stun_attr_ice_controlling_set_tiebreaker_value(
                                            handle h_attr, uint64_t tiebreak);

/* ========================================================================== */

#define stun_attr_ice_controlled_get_tiebreaker_value(h_attr, tiebreak) \
            stun_attr_ice_controlling_get_tiebreaker_value(h_attr, tiebreak)

#define stun_attr_ice_controlled_set_tiebreaker_value(h_attr, tiebreak) \
            stun_attr_ice_controlling_set_tiebreaker_value(h_attr, tiebreak)
        
/* ========================================================================== */
/* ========================================================================== */
/* ========================================================================== */

int32_t stun_extended_attr_get_attr_type(handle h_attr, uint16_t *attr_type);

/* ========================================================================== */

/** stun message utility functions */

int32_t stun_msg_utils_add_unknown_attributes(
                            handle h_msg, handle *pah_attr, uint32_t num);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
