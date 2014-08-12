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

# Makefile for creating sample application programs

ICE_LIB_DEST_PATH := $(shell pwd)/../lib

ICE_FULL_AGENT := ice_full_agent
ICE_LITE_AGENT := ice_lite_agent
ICE_LITE_AGENT_DUAL_STACK := ice_lite_agent_dual_stack
STUN_KEEPALIVE := stun_keepalive
ICE_AGENT_DEMO := ice_agent_demo
MB_ICE_WARRIOR := mb_ice_warrior
GEN_LIC_KEY := gen_lic_key
TARGET := all
SRC := stun_keepalive.c ice_full_agent.c ice_lite_agent.c \
	ice_agent_demo.c mb_ice_warrior.c verify_key.c \
	stun_keepalive_refresh.c ice_lite_agent_dual_stack.c gen_key.c

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
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lcrypto -lm -lrt -ldl -lpthread

ICE_FULL_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_ice.a \
	$(ICE_LIB_DEST_PATH)/lib_turn.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_binding.a \
	$(ICE_LIB_DEST_PATH)/lib_ice_conncheck.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lcrypto -lm -lrt -ldl -lpthread

STUN_BIND_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_stun_binding.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lcrypto -lm -lrt -ldl -lpthread


CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX

OBJ:=$(SRC:c=o)

.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

#$(TARGET) : clean $(ICE_FULL_AGENT) $(STUN_KEEPALIVE) $(ICE_AGENT_DEMO) $(MB_ICE_WARRIOR)
$(TARGET) : clean $(ICE_FULL_AGENT) $(STUN_KEEPALIVE) $(ICE_LITE_AGENT) \
	$(ICE_AGENT_DEMO) $(MB_ICE_WARRIOR) $(ICE_LITE_AGENT_DUAL_STACK) \
	$(GEN_LIC_KEY)

$(ICE_LITE_AGENT) :
	@echo "Creating ice lite sample... " $(TARGET) 
	$(CC) $(CFLAGS) $(ICE_LITE_INC) -o ice_lite_agent.o ice_lite_agent.c
	$(CC) ice_lite_agent.o -o $(ICE_LITE_AGENT) $(ICE_LITE_LIBRARY)
	#$(CC) ice_lite_agent.o -o $(ICE_LITE_AGENT) -Wl,-Map,ice_lite.map $(ICE_LITE_LIBRARY)

$(ICE_LITE_AGENT_DUAL_STACK) :
	@echo "Creating ice lite dual stack sample... " $(TARGET) 
	$(CC) $(CFLAGS) $(ICE_LITE_INC) -o ice_lite_agent_dual_stack.o ice_lite_agent_dual_stack.c
	$(CC) ice_lite_agent_dual_stack.o -o $(ICE_LITE_AGENT_DUAL_STACK) $(ICE_LITE_LIBRARY)


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

$(MB_ICE_WARRIOR) :
	@echo "Creating MindBricks ice warrior.... " $(TARGET)
	$(CC) $(CFLAGS) $(ICE_FULL_INC) -o mb_ice_warrior.o mb_ice_warrior.c
	$(CC) $(CFLAGS) $(ICE_FULL_INC) -o verify_key.o verify_key.c
	$(CC) mb_ice_warrior.o verify_key.o -o $(MB_ICE_WARRIOR) $(ICE_FULL_LIBRARY)
	#$(CC) mb_ice_warrior.o -o $(MB_ICE_WARRIOR)  -Wl,-Map,mb_ice_warrior.map  $(ICE_FULL_LIBRARY)

$(STUN_KEEPALIVE):
	@echo "Creating stun keepalive sample... " $(TARGET)
	$(CC) $(CFLAGS) -o stun_keepalive.o stun_keepalive.c
	$(CC) stun_keepalive.o -o $(STUN_KEEPALIVE) $(STUN_BIND_LIBRARY)
	#$(CC) stun_keepalive.o -o $(STUN_KEEPALIVE)  -Wl,-Map,keep_alive.map $(STUN_BIND_LIBRARY)

$(GEN_LIC_KEY):
	@echo "Creating license key generator ... " $(TARGET)
	$(CC) $(CFLAGS) -o gen_lic_key.o gen_lic_key.c
	$(CC) gen_lic_key.o -o $(GEN_LIC_KEY) -lssl -lcrypto

clean_obj:
	rm -rf $(OBJ)

clean:
	@echo "Removing all sample ... "
	rm -rf $(ICE_LITE_AGENT) $(ICE_FULL_AGENT) $(STUN_KEEPALIVE) \
		$(ICE_AGENT_DEMO) $(MB_ICE_WARRIOR) $(ICE_LITE_AGENT_DUAL_STACK) \
		$(GEN_LIC_KEY) $(OBJ)

