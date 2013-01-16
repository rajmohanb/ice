#*******************************************************************************
#                                                                              #
#               Copyright (C) 2009-2012, MindBricks Technologies               #
#                  Rajmohan Banavi (rajmohan@mindbricks.com)                   #
#                     MindBricks Confidential Proprietary.                     #
#                            All Rights Reserved.                              #
#                                                                              #
#*******************************************************************************
#                                                                              #
# This document contains information that is confidential and proprietary to   #
# MindBricks Technologies. No part of this document may be reproduced in any   #
# form whatsoever without prior written approval from MindBricks Technologies. #
#                                                                              #
#******************************************************************************/

# build customization flags
MB_ENABLE_ICE_DEBUG := y

# path where the built ice stack libraries will be placed. The application
# developer can modify this variable as per their environment
ICE_LIB_DEST_PATH := /root/ICE/lib

# application specific additional include path which will be included during 
# compilation of the ice stack. When the ICE stack is integrated into the 
# application, this variable can be modified as per the environment.
ICE_APP_INCLUDE_PATH := .

# additional compilation flags that can be passed by the application. These 
# additional flags may include flags related to debugging among others. If
# the target platform architecture is big endian, then add the flag - 
# -DIS_LITTLE_ENDIAN, else add -DIS_BIG_ENDIAN
# -DMB_LOG_RX_TX_MSGS - enables logging of outgoing stun messages
# -DMB_IGNORE_SRFLEX_CONN_CHECKS - ignore conn checks with server reflex cands
ICE_APP_CFLAGS := -DIS_LITTLE_ENDIAN -DMB_LOG_RX_TX_MSGS

ifeq ($(strip $(MB_ENABLE_ICE_DEBUG)), y)
ICE_APP_CFLAGS += -g -DDEBUG1 -DMB_SUPPORT_3489 -DDEBUG #-DDEBUG2
endif

export ICE_APP_INCLUDE_PATH
export ICE_LIB_DEST_PATH
export ICE_APP_CFLAGS


full:
	make -C stun/enc_dec/src/
	make -C stun/msg_layer/src/
	make -C stun/txn/src/
	make -C turn/src/
	make -C conn_check/src/
	make -C ice/src/
	make -C binding/src/
	make -C platform/src/
	make -C ice_lite/src/
	make -C turns/src/
	make -C stuns/src/

lite:
	make -C stun/enc_dec/src/
	make -C stun/msg_layer/src/
	make -C stun/txn/src/
	make -C conn_check/src/
	make -C ice_lite/src/
	make -C binding/src/
	make -C platform/src/


clean:
	make -C stun/enc_dec/src/ clean
	make -C stun/msg_layer/src/ clean
	make -C stun/txn/src/ clean
	make -C turn/src/ clean
	make -C conn_check/src/ clean
	make -C ice/src/ clean
	make -C ice_lite/src/ clean
	make -C binding/src/ clean
	make -C platform/src/ clean
	make -C turns/src/ clean
	make -C stuns/src/ clean

