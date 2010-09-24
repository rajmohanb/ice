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

#ifndef STUN_BASE__H
#define STUN_BASE__H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "platform/inc/platform_api.h"


#ifdef WINDOWS

typedef     unsigned short  u_int16;
typedef     signed short    s_int16;
typedef     unsigned int    u_int32;
typedef     signed int      s_int32;
typedef     unsigned long long u_int64;
typedef     signed long long s_int64;
typedef     unsigned char   u_char;
typedef     signed char     s_char;
typedef     unsigned char   u_int8;
typedef     char            s_int8;

#endif


typedef     uint8_t         u_char;
typedef     char            s_char;

typedef     bool            bool_t;
typedef     void*           handle;

#define NE !=
#define LT <
#define GT >
#define LE <=
#define GE >=
#define EQ ==
#define AND &&
#define OR ||

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE
#endif


#ifndef NULL
#define     NULL            0x00
#endif

#define STUN_OK             0
#define STUN_INT_ERROR      1
#define STUN_MEM_ERROR      2
#define STUN_INVALID_PARAMS 3
#define STUN_NOT_FOUND      4
#define STUN_TERMINATED     5
#define STUN_ENCODE_FAILED  6
#define STUN_DECODE_FAILED  7
#define STUN_MEM_INSUF      8
#define STUN_NOT_SUPPORTED  9
#define STUN_TRANSPORT_FAIL 10
#define STUN_VALIDATON_FAIL 11
#define STUN_NO_RESOURCE    12


#define stun_malloc platform_malloc
#define stun_calloc platform_calloc
#define stun_free(x) { if(x) platform_free(x); x = NULL; }
#define stun_memset platform_memset
#define stun_memcpy platform_memcpy
#define stun_memcmp platform_memcmp
#define platform_md5 MD5
#define platform_hmac_sha platform_hmac_sha
#define stun_strcpy strcpy
#define stun_strncpy strncpy
#define stun_snprintf snprintf
#define stun_sprintf sprintf
#define stun_strcmp strcmp
#define stun_strncmp strncmp
#define stun_strlen strlen
#define platform_time time
#define platform_rand rand
#define platform_srand srand


#define ICE_IP_ADDR_MAX_LEN     46


typedef enum
{
    LOG_SEV_CRITICAL,
    LOG_SEV_ERROR,
    LOG_SEV_WARNING,
    LOG_SEV_INFO,
    LOG_SEV_DEBUG,
    LOG_SEV_MAX,
} stun_log_level_t;


typedef enum
{
    STUN_INET_ADDR_IPV4,
    STUN_INET_ADDR_IPV6,
    STUN_INET_ADDR_MAX,
} stun_inet_addr_type_t;


typedef struct 
{
    stun_inet_addr_type_t   host_type;
    u_char                  ip_addr[ICE_IP_ADDR_MAX_LEN];
    uint32_t                port;
} stun_inet_addr_t;


#define ICE_LOG app_log

void app_log(/** char *file_name, uint32_t line_num, */
                stun_log_level_t level, char *format, ...);


/******************************************************************************/

#ifdef __cplusplus
}
#endif

#endif

/******************************************************************************/