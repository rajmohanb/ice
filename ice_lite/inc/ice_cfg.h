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

#ifndef ICE_CFG__H
#define ICE_CFG__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define ICE_IP_ADDR_MAX_LEN     46
#define ICE_FOUNDATION_MAX_LEN  128


#define ICE_CHECK_LIST_MAX_SIZE     100
#define ICE_CANDIDATES_MAX_SIZE     10

#define TURN_SVR_IP_ADDR_MAX_LEN    16
#define STUN_SVR_IP_ADDR_MAX_LEN    16

#define ICE_MAX_CONCURRENT_SESSIONS 4
#define ICE_MAX_CANDIDATE_PAIRS     18

#define TURN_SERVER_DEFAULT_PORT 3478
#define STUN_SERVER_DEFAULT_PORT 3478

#define TURN_MAX_USERNAME_LEN   128
#define TURN_MAX_PASSWORD_LEN   128
#define TURN_MAX_REALM_LEN      64

#define SOFTWARE_CLIENT_NAME_LEN 100

/** candidate priority */

/** candidate type preference: [max = 126] & [min = 0] */
#define CAND_TYPE_PREF_HOST_CANDIDATE       126
#define CAND_TYPE_PREF_PRFLX_CANDIDATE      110
#define CAND_TYPE_PREF_SRFLX_CANDIDATE      100
#define CAND_TYPE_PREF_RELAY_CANDIDATE      0

/** local host address preference [max = 65536] & [min = 0] */
#define LOCAL_IP_PRECEDENCE             65535
#define LOCAL_PREF_IPV4                 65535
#define LOCAL_PREF_IPV4                 65535

/** max media streams per ice session */
#define ICE_MAX_MEDIA_STREAMS   2

/** max components per media stream */
#define ICE_MAX_COMPONENTS      2

/** max number of valid pairs */
#define ICE_MAX_VALID_LIST_PAIRS    2

/** 
 * maximum number of gathered candidates per component of per media stream
 */
#define ICE_MAX_GATHERED_CANDS  3

/** component id */
#define RTP_COMPONENT_ID        1
#define RTCP_COMPONENT_ID       2

/** Ta and RTO values for gathering */
#define TA_VAL_FOR_GATHERING    20 /* ms */
#define RTO_VAL_FOR_GATHERING   100

/** Ta and RTO values for connectivity checks */
#define TA_VAL_FOR_CHECKS       20
#define RTO_VAL_FOR_CHECKS      100

/** max length of username and password tokens used for connectivity checks */
#define ICE_MAX_UFRAG_LEN       256
#define ICE_MAX_PWD_LEN         256

#define TRANSPORT_MTU_SIZE      1500

/******************************************************************************/


#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/
