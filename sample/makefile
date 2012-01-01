#*******************************************************************************
#                                                                              #
#             Copyright (C) 2009-2012, MindBricks Technologies                 #
#			         MindBricks Confidential Proprietary.                      #
#                             All Rights Reserved.                             #
#                                                                              #
#*******************************************************************************
#                                                                              #
# This document contains information that is confidential and proprietary to   #
# MindBricks Technologies. No part of this document may be reproduced in any   #
# form whatsoever without prior written approval from MindBricks Technologies. #
#                                                                              #
#******************************************************************************/

# Makefile for creating sample application programs

ICE_LIB_DEST_PATH := /root/ICE/lib

ICE_FULL_AGENT := ice_full_agent
ICE_LITE_AGENT := ice_lite_agent
STUN_KEEPALIVE := stun_keepalive
ICE_AGENT_DEMO := ice_agent_demo
TARGET := all
SRC := stun_keepalive.c ice_full_agent.c ice_lite_agent.c ice_agent_demo.c

# Include header file path
INCLUDE :=-I ../ -I ../binding/inc -I ../stun/msg_layer/inc -I ../ \
	-I ../stun/enc_dec/inc -I ../stun/txn/inc -I ../inc -I ../

ICE_LITE_INC :=-I ../ice_lite/inc
ICE_FULL_INC :=-I ../ice/inc -I ../turn/inc

ICE_LITE_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_ice_lite.a \
	$(ICE_LIB_DEST_PATH)/lib_ice_conncheck.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lm -lrt -ldl

ICE_FULL_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_ice.a \
	$(ICE_LIB_DEST_PATH)/lib_turn.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_binding.a \
	$(ICE_LIB_DEST_PATH)/lib_ice_conncheck.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lm -lrt -ldl

STUN_BIND_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_stun_binding.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lm -lrt -ldl


CFLAGS += -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX

OBJ:=$(SRC:c=o)

.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(ICE_FULL_AGENT) $(STUN_KEEPALIVE) $(ICE_LITE_AGENT) $(ICE_AGENT_DEMO)

$(ICE_LITE_AGENT) :
	@echo "Creating ice lite sample... " $(TARGET) 
	$(CC) $(CFLAGS) $(ICE_LITE_INC) -o ice_lite_agent.o ice_lite_agent.c
	$(CC) ice_lite_agent.o -o $(ICE_LITE_AGENT) $(ICE_LITE_LIBRARY)
	#$(CC) ice_lite_agent.o -o $(ICE_LITE_AGENT) -Wl,-Map,ice_lite.map $(ICE_LITE_LIBRARY)

$(ICE_FULL_AGENT) :
	@echo "Creating ice full sample... " $(TARGET)
	$(CC) $(CFLAGS) $(ICE_FULL_INC) -o ice_full_agent.o ice_full_agent.c
	$(CC) ice_full_agent.o -o $(ICE_FULL_AGENT) $(ICE_FULL_LIBRARY)
	#$(CC) ice_full_agent.o -o $(ICE_FULL_AGENT)  -Wl,-Map,ice_full.map  $(ICE_FULL_LIBRARY)

$(ICE_AGENT_DEMO) :
	@echo "Creating ice agent demo.... " $(TARGET)
	$(CC) $(CFLAGS) $(ICE_FULL_INC) -o ice_agent_demo.o ice_agent_demo.c
	$(CC) ice_agent_demo.o -o $(ICE_AGENT_DEMO) $(ICE_FULL_LIBRARY)
	#$(CC) ice_agent_demo.o -o $(ICE_AGENT_DEMO)  -Wl,-Map,ice_agent_demo.map  $(ICE_FULL_LIBRARY)

$(STUN_KEEPALIVE):
	@echo "Creating stun keepalive sample... " $(TARGET)
	$(CC) $(CFLAGS) -o stun_keepalive.o stun_keepalive.c
	$(CC) stun_keepalive.o -o $(STUN_KEEPALIVE) $(STUN_BIND_LIBRARY)
	#$(CC) stun_keepalive.o -o $(STUN_KEEPALIVE)  -Wl,-Map,keep_alive.map $(STUN_BIND_LIBRARY)

clean_obj:
	rm -rf $(OBJ)

clean:
	@echo "Removing all sample ... "
	rm -rf $(ICE_LITE_AGENT) $(ICE_FULL_AGENT) $(STUN_KEEPALIVE) $(ICE_AGENT_DEMO) $(OBJ)

