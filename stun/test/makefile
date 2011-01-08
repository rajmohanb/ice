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

TARGET := stun_test

SRC :=  test_stun.c

INCLUDE :=-I ../msg_layer/inc -I ../../ -I ../enc_dec/inc -I ../txn/inc

LIBRARY := ../msg_layer/lib/stun_msg_layer.a ../enc_dec/lib/stun_parse_format.a ../txn/lib/stun_txn.a -lm -lrt -ldl

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX 

OBJ:=$(SRC:c=o)

#
#object Build Rules
#
.c.o :
	@echo [CC] 	$< ...
	@$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : $(OBJ)
	@echo "Creating Executable " $(TARGET)
	@$(CC) $(OBJ) -o $(TARGET)  $(LIBRARY)

clean:
	@echo "Removing Executable" $(TARGET)
	@rm -rf $(OBJ) $(TARGET)



