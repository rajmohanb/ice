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

#ifndef STUN_BINDING_UTILS__H
#define STUN_BINDING_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t stun_binding_utils_create_msg(stun_msg_type_t msg_type, handle *h_req);


int32_t stun_binding_utils_start_refresh_timer(stun_binding_session_t *session);


int32_t stun_binding_utils_initiate_session_refresh(
                                        stun_binding_session_t *session);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
