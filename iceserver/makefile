#*******************************************************************************
#                                                                              #
#               Copyright (C) 2009-2013, MindBricks Technologies               #
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

# Makefile for creating mindbricks ice server

ICE_LIB_DEST_PATH := $(shell pwd)/../lib

ICE_SERVER := mb_ice_server
TARGET := all
SRC := ice_server.c iceserver_transport.c iceserver_user.c

# Include header file path
INCLUDE :=-I . -I ../stuns/inc -I ../turns/inc -I ../binding/inc \
	-I ../stun/msg_layer/inc -I ../ \
	-I ../stun/enc_dec/inc -I ../stun/txn/inc -I ../inc -I ../ \
	-I /usr/include/postgresql/

ICE_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_turns.a \
	$(ICE_LIB_DEST_PATH)/lib_stuns.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lcrypto -lm -lpthread -lrt -ldl

POSTGRES_LIB := -lpq

CFLAGS += -g -Wall -Wstrict-prototypes -c -DLINUX -DMB_ENABLE_ICE \
		  -DMB_ENABLE_TURN $(INCLUDE) -DMB_SERVER_DEV -DMB_SMP_SUPPORT \
		  -DMB_USE_EPOLL

OBJ:=$(SRC:c=o)

.c.o :
	echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(ICE_SERVER)

$(ICE_SERVER) : $(OBJ)
	@echo "Creating mindbricks ice server ... " $(TARGET) 
	$(CC) $(CFLAGS) $(INCLUDE) -o ice_server.o ice_server.c
	$(CC) $(OBJ) -o $(ICE_SERVER) $(ICE_LIBRARY) $(POSTGRES_LIB)

clean_obj:
	rm -rf $(OBJ)

clean:
	@echo "Removing all objects and binaries ... "
	rm -rf $(ICE_SERVER) $(OBJ)

