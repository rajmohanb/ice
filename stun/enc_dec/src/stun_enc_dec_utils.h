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

#ifndef STUN_ENC_DEC_UTILS__H
#define STUN_ENC_DEC_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

int32_t stun_enc_dec_utils_get_long_term_cred_hmac_key(handle h_msg, 
                                stun_auth_params_t *auth_params, u_char *key);

uint16_t stun_tlv_utils_get_stun_msg_type(stun_msg_t *msg);

uint32_t stun_enc_dec_utils_print_binary_buffer(
        u_char *dest, uint32_t dest_len, u_char *src, uint32_t src_len);

int32_t stun_enc_dec_utils_print_msg_header(
                        stun_msg_t *msg, u_char *buf, uint32_t *buf_len);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
