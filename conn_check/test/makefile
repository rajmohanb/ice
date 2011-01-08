#*******************************************************************************
# 
#             Copyright (C) 2009-2011, MindBricks Technologies
#			         MindBricks Confidential Proprietary.
#                             All Rights Reserved.
#
#********************************************************************************
#
# This document contains information that is confidential and proprietary to 
# MindBricks Technologies. No part of this document may be reproduced in any 
# form whatsoever without prior written approval from MindBricks Technologies.
#
#*******************************************************************************/

# Macros
OG_CC := og_cc
IC_CC := ig_cc

TARGET := all

SRC :=  test_cc_lib_og.c test_cc_lib_ic.c

INCLUDE :=-I ../../ -I ../../stun/msg_layer/inc -I ../ -I ../../stun/parse_format/inc -I ../../stun/transaction/inc -I ../inc

LIBRARY := ../lib/conn_check.a ../../stun/parse_format/lib/stun_parse_format.a ../../stun/transaction/lib/stun_txn.a ../../stun/msg_layer/lib/stun_msg_layer.a ../../platform/lib/lib_platform.a -lssl -lm -lrt -ldl

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
	$(CC) test_cc_lib_og.o  -o $(OG_CC)  $(LIBRARY)
	$(CC) test_cc_lib_ic.o  -o $(IC_CC)  $(LIBRARY)

clean:
	@echo "Removing Executable" $(TARGET)
	@rm -rf $(OBJ) $(TARGET)

