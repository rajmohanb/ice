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

# Makefile for creating stun binding library

# Macros

# stun binding library
LIB := lib_stun_binding.a

# stun binding layer source files
SRC = stun_binding_api.c stun_binding_utils.c

# Include header files
INCLUDE := -I ../../ -I ../inc -I ../../stun/txn/inc \
	-I ../../stun/msg_layer/inc -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes $(ICE_APP_CFLAGS) $(INCLUDE)

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
