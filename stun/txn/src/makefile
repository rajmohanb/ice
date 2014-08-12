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

# Makefile for creating stun transaction library

# Macros

# stun transaction library file
LIB := lib_stun_txn.a

# stun transaction source files
SRC = stun_txn_api.c stun_txn_fsm.c stun_txn_table.c stun_txn_utils.c

# Include header files
INCLUDE := -I ../inc -I ../../../ -I ../../msg_layer/src \
	-I ../../msg_layer/inc -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes $(ICE_APP_CFLAGS) $(INCLUDE) \
		  -DMB_ENABLE_TURN -DMB_ENABLE_ICE

OBJS:=$(SRC:c=o)
#
#object Build Rules
#
.c.o :
	@echo "[CC] " $< ...
	@$(CC) $(CFLAGS) -o $*.o $<

archive:$(OBJS)
	@echo "Building library " $(LIB)
	@$(AR) $(ARFLAGS) $(LIB) $(OBJS) 
	@mv $(LIB) $(ICE_LIB_DEST_PATH)

clean:
	@echo "Cleaning library " $(LIB)
	@rm -rf *.o $(ICE_LIB_DEST_PATH)/$(LIB)
