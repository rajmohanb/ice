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

#ifndef ICE_SERVER__H
#define ICE_SERVER__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

/** some configuration stuff */
#define MB_ICE_SERVER   "MindBricks ICE Server 0.1"
#define ICE_SERVER_INTERNAL_TIMER_PORT    34343
#define ICE_SERVER_TURN_PORT    3478
#define NET_INTERFACE   "eth0"


typedef struct
{
    handle h_turns_inst;

    pthread_t tid;

} mb_ice_server_t;


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
