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

ICE_LIB_DEST_PATH := /root/ICE/lib

ICE_SERVER := mb_ice_server
TARGET := all
SRC := ice_server.c iceserver_transport.c iceserver_user.c

# Include header file path
INCLUDE :=-I . -I ../turns/inc -I ../binding/inc -I ../stun/msg_layer/inc -I ../ \
	-I ../stun/enc_dec/inc -I ../stun/txn/inc -I ../inc -I ../

TURNS_LIBRARY := $(ICE_LIB_DEST_PATH)/lib_turns.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_binding.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_encdec.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_txn.a \
	$(ICE_LIB_DEST_PATH)/lib_stun_msg.a \
	$(ICE_LIB_DEST_PATH)/lib_platform.a -lssl -lcrypto -lm -lrt -ldl

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX

OBJ:=$(SRC:c=o)

.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(ICE_SERVER)

$(ICE_SERVER) : $(OBJ)
	@echo "Creating mindbricks ice server ... " $(TARGET) 
	$(CC) $(CFLAGS) $(INCLUDE) -o ice_server.o ice_server.c
	$(CC) $(OBJ) -o $(ICE_SERVER) $(TURNS_LIBRARY)

clean_obj:
	rm -rf $(OBJ)

clean:
	@echo "Removing all objects and binaries ... "
	rm -rf $(ICE_SERVER) $(OBJ)

