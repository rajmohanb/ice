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

#ifndef STUNS_UTILS__H
#define STUNS_UTILS__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


int32_t stuns_utils_send_error_resp(stuns_instance_t *instance, 
                        stuns_rx_stun_pkt_t *stun_pkt, uint32_t error_code, 
                        char *reason, handle *pah_attr, uint32_t num_attr);

int32_t stuns_utils_send_success_resp(
            stuns_instance_t *instance, stuns_rx_stun_pkt_t *stun_pkt);

int32_t stuns_utils_process_stun_binding_request(
                stuns_instance_t *instance, stuns_rx_stun_pkt_t *stun_pkt);



/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
