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

#ifndef STUN_ATTR_ENC_DEC__H
#define STUN_ATTR_ENC_DEC__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t stun_attr_encode(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print(stun_msg_t *msg, u_char *buf, uint32_t *buf_len);



int32_t stun_attr_encode_mapped_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_mapped_address(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_mapped_address(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);



int32_t stun_attr_encode_username(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_username(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_username(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_message_integrity(handle h_msg, 
        stun_attr_hdr_t *attr, u_char *msg_start, u_char *buf, 
        uint32_t max_len, stun_auth_params_t *auth, uint32_t *len);

int32_t stun_attr_decode_message_integrity(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_message_integrity(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_error_code(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_error_code(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_error_code(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_unknown_attributes(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_unknown_attributes(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_unknown_attributes(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_realm(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_realm(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_realm(
                stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_nonce(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_nonce(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_nonce(
                stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_xor_mapped_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_xor_mapped_address(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_xor_mapped_address(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_software(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_software(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_software(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_alternate_server(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_alternate_server(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_alternate_server(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_fingerprint(stun_attr_hdr_t *attr, 
            u_char *msg_start, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_fingerprint(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_fingerprint(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);

#ifdef MB_ENABLE_TURN
int32_t stun_attr_encode_channel_number(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_channel_number(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_channel_number(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_lifetime(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_lifetime(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_lifetime(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_xor_peer_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_xor_peer_address(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_xor_peer_address(
                            stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_data(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_data(u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_data(stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_xor_relayed_address(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_xor_relayed_address(u_char *buf_head, 
                    u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_xor_relayed_address(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_even_port(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_even_port(u_char *buf_head, 
                    u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_even_port(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_requested_transport(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_requested_transport(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_requested_transport(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_dont_fragment(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_dont_fragment(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_dont_fragment(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_reservation_token(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_reservation_token(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_reservation_token(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);

#endif

#ifdef MB_ENABLE_ICE

int32_t stun_attr_encode_priority(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_priority(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_priority(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_use_candidate(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_use_candidate(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_use_candidate(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_ice_controlled(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_ice_controlled(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_ice_controlled(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);


int32_t stun_attr_encode_ice_controlling(stun_attr_hdr_t *attr, 
                u_char *buf_head, u_char *buf, uint32_t max_len, uint32_t *len);

int32_t stun_attr_decode_ice_controlling(u_char *buf_head, 
                u_char **buf, u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_ice_controlling(
                    stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);

#endif

int32_t stun_attr_decode_extended_attr(uint16_t attr_type, 
                                u_char *buf_head, u_char **buf, 
                                u_char *buf_end, stun_attr_hdr_t **attr);

int32_t stun_attr_print_extended_attr(
                stun_attr_hdr_t *attr, u_char *buf, uint32_t *len);

/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
