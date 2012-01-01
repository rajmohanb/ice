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

# Makefile for creating ice connectivity check library

# Macros

# connectivity check library
LIB := lib_ice_conncheck.a

# connectivity check source files
SRC = conn_check_api.c conn_check_session_fsm.c conn_check_utils.c

# Include header files
INCLUDE := -I ../../ -I ../inc -I ../../stun/txn/inc \
	-I ../../stun/msg_layer/inc -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes $(ICE_APP_CFLAGS)  $(INCLUDE) \
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
