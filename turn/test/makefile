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

# Macros

TARGET := turn_lib_test

SRC :=  test_turn_lib.c

INCLUDE :=-I ../../ -I ../../stun/msg_layer/inc -I ../ -I ../../stun/parse_format/inc -I ../../stun/transaction/inc -I ../inc

LIBRARY := ../lib/turn.a ../../stun/msg_layer/lib/stun_msg_layer.a ../../stun/parse_format/lib/stun_parse_format.a ../../stun/transaction/lib/stun_txn.a ../../platform/lib/lib_platform.a -lssl -lm -lrt -ldl

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX 

OBJ:=$(SRC:c=o)

#
#object Build Rules
#
.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(OBJ)
	@echo "Creating Executable " $(TARGET)
	@$(CC) $(OBJ) -o $(TARGET)  $(LIBRARY)

clean:
	@echo "Removing Executable" $(TARGET)
	@rm -rf $(OBJ) $(TARGET)

