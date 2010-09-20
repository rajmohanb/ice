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

#ifndef STUN_MSG__H
#define STUN_MSG__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"


#define STUN_TXN_ID_BYTES           12

#define MSG_INTEGRITY_HMAC_BYTES    20

#define STUN_ATTR_FINGERPRINT_SIZE  4

#define DEFAULT_MTU                 1500

#define STUN_MAGIC_COOKIE           0x2112A442

#define STUN_RESERVATION_TOKEN_LENGTH   8

#define MAX_NONCE_VAL_BYTES         763
#define MAX_REALM_VAL_BYTES         763
#define MAX_ERROR_CODE_REASON_BYTES 763
#define MAX_SOFTWARE_VAL_BYTES      763
    


typedef struct {

    /** 
     * STUN attribute type 
     */
    stun_attribute_type_t   type;

    /** 
     * STUN attribute length 
     */
    uint16_t                length;

} stun_attr_hdr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t    hdr;

    /**
     * mapped address family
     */
    stun_addr_family_type_t   family;

    /**
     * mapped address port
     */
    uint16_t                 port;

    /**
     * mapped address
     */
    u_char                  address[MAX_MAPPED_ADDRESS_LEN];

} stun_mapped_addr_attr_t;


typedef stun_mapped_addr_attr_t stun_xor_mapped_addr_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * username
     */
    u_char              *username;

} stun_username_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * HMAC
     */
    u_char              hmac[MSG_INTEGRITY_HMAC_BYTES];

    /**
     * indicates the number of bytes after which the message 
     * integrity attribute is present in the raw stun message.
     */
    uint32_t            position;

} stun_msg_integrity_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * finger print value
     */
    uint32_t            value;

    /**
     * indicates the number of bytes after which the fingerprint 
     * attribute is present in the raw stun message.
     */
    uint32_t            position;

} stun_fingerprint_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * error code
     */
    uint32_t            code;

    /**
     * reason phrase
     */
    u_char              *reason;

} stun_error_code_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * realm
     */
    u_char              *realm;

} stun_realm_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * nonce
     */
    u_char              *nonce;

} stun_nonce_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * list of unknown attribute types
     */
    uint16_t            count;
    uint16_t            attr_types[MAX_UNKNOWN_ATTRIBUTE_TYPES];

} stun_unknown_attributes_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * Manufacturer name and version
     */
    u_char              *software;

} stun_software_attr_t;



typedef stun_mapped_addr_attr_t stun_alt_server_attr_t;


#ifdef ENABLE_TURN

typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * channel number
     */
    uint32_t            channel_number;

    /**
     * reserved for future use
     */
    uint32_t            rffu;

} stun_channel_number_attr_t;



typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * lifetime duration in secs
     */
    uint32_t            lifetime;

} stun_lifetime_attr_t;



typedef stun_mapped_addr_attr_t stun_xor_peer_addr_attr_t;

typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * length of data
     */
    uint32_t            length;

    /**
     * application data
     */
    u_char              *data;

} stun_data_attr_t;


typedef stun_mapped_addr_attr_t stun_xor_relayed_addr_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * flag
     */
    bool_t              flag;

} stun_even_port_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * protocol
     */
    u_char              protocol;

} stun_req_transport_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t    hdr;

    /** there is no value associated with this attribute */

} stun_dont_fragment_attr_t;


typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    u_char              token[STUN_RESERVATION_TOKEN_LENGTH];

} stun_reservation_token_attr_t;

#endif

#ifdef ENABLE_ICE

typedef struct
{
    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    uint32_t            priority;

} stun_priority_attr_t;


typedef struct
{
    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t    hdr;

} stun_use_candidate_attr_t;


typedef struct
{
    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t    hdr;

    uint64_t           random_num;

} stun_ice_controlled_attr_t;


typedef struct
{
    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t    hdr;

    uint64_t           random_num;

} stun_ice_controlling_attr_t;


#endif

typedef struct {

    /**
     * common STUN attribute header
     */
    stun_attr_hdr_t     hdr;

    /**
     * stun attribute type value
     */
    uint16_t            attr_type_value; 

    /**
     * generic attribute value
     */
    u_char              value[STUN_EXT_ATTR_VALUE_LEN];

} stun_extended_attr_t;


typedef struct {

    /**
     * STUN message class
     */
    stun_msg_type_t     class_type;

    /**
     * STUN message method
     */
    stun_method_type_t  method;

    /**
     * STUN message length
     */
    uint16_t            length;

    /**
     * Magic Cookie
     */
    uint32_t            magic_cookie;

    /**
     * transaction id (98 bits)
     */
    u_char              trans_id[STUN_TXN_ID_BYTES];

} stun_msg_hdr_t;




typedef struct {

    /**
     * STUN message header
     */
    stun_msg_hdr_t      hdr;

    /**
     * number of attributes in this STUN message
     */
    uint16_t            attr_count;

    /**
     * series of attributes
     */
    stun_attr_hdr_t     *pas_attr[MAX_STUN_ATTRIBUTES];

    /**
     * raw stun message
     */
    u_char              *stun_msg;

    /**
     * length of stun message
     */
    uint32_t            stun_msg_len;

} stun_msg_t;



typedef struct {

    uint32_t            mtu;

} stun_msg_layer_instance_t;



/******************************************************************************/

#ifdef __cplusplus

#endif

#endif

/******************************************************************************/
