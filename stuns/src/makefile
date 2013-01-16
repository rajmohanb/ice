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

# Makefile for creating turn library

# turn library file name
LIB := lib_stuns.a

# turn source files
SRC = stuns_api.c stuns_utils.c #stuns_table.c stuns_alloc_fsm.c

# Include header files
INCLUDE := -I. -I ../../ -I ../inc -I ../../stun/txn/inc \
	-I ../../stun/msg_layer/inc -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes $(ICE_APP_CFLAGS) \
		  -DMB_ENABLE_ICE $(INCLUDE)

OBJS:=$(SRC:c=o)

.c.o :
	@echo "[CC] " $< ...
	$(CC) $(CFLAGS) -o $*.o $<

archive:$(OBJS)
	@echo "Building library " $(LIB)
	@$(AR) $(ARFLAGS) $(LIB) $(OBJS) 
	@mv $(LIB) $(ICE_LIB_DEST_PATH)

clean:
	@echo "Cleaning library " $(LIB)
	@rm -rf *.o $(ICE_LIB_DEST_PATH)/$(LIB)
