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

#ifndef STUN_UTILS__H
#define STUN_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#include "stun_base.h"


handle stun_utils_create_attr(stun_attribute_type_t attr_type);

int32_t stun_utils_destroy_attr(handle stun_attr);

int32_t stun_msg_utils_add_unknown_attributes(
                            handle h_msg, handle *pah_attr, uint32_t num);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
