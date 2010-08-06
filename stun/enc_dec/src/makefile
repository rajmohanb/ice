#*******************************************************************************
# 
#             Copyright (C) 2009-2010, MindBricks Technologies
#			         MindBricks Confidential Proprietary.
#                             All Rights Reserved.
#
#*******************************************************************************
#
# This document contains information that is confidential and proprietary to 
# MindBricks Technologies. No part of this document may be reproduced in any 
# form whatsoever without prior written approval from MindBricks Technologies.
#
#******************************************************************************/

# Makefile for creating stun encoder and decoder library

# Macros

# encoder and decoder library file
LIB := lib_stun_encdec.a

# encoder and decoder library source files
SRC = stun_enc_dec_api.c stun_attr_enc_dec.c stun_enc_dec_utils.c

# Include header files
INCLUDE := -I ../inc -I ../../../ -I ../../msg_layer/src \
	-I ../../msg_layer/inc -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes $(ICE_APP_CFLAGS) $(INCLUDE) \
		  -DENABLE_TURN -DENABLE_ICE 

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
