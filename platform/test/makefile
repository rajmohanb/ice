#*******************************************************************************
# 
#             Copyright (C) 2009-2010, MindBricks Technologies
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

PLATFORM_LIB := ../lib

TARGET := test_platform

SRC = test_platform_lib.c

LIBRARY := ../lib/lib_platform.a -lrt -lssl

INCLUDE := -I ../inc -I ../../

CFLAGS += -g -Wall -Wstrict-prototypes -c  $(INCLUDE) 

OBJS:=$(SRC:c=o)
#
#object Build Rules
#
.c.o :
	@echo "[CC] " $< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : $(OBJS)
	@echo "Creating platform test program " $(TARGET)
	@$(CC) $(OBJS) -g -o $(TARGET)  $(LIBRARY)
	@echo "Done!" 

clean:
	@echo "Cleaning test program " $(TARGET)
	@rm -rf *.o $(TARGET) core*
