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

#ifndef ICE_ADDR_SEL__H
#define ICE_ADDR_SEL__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

typedef struct
{
    ice_transport_t *src;
    ice_transport_t *dest;
    bool_t          reachable;
} ice_rfc3484_addr_pair_t;


int32_t ice_addr_sel_determine_destination_address(
                    ice_rfc3484_addr_pair_t *addr_list, int32_t num);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
