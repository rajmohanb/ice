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

LIB := lib_platform.a
SRC = platform_api.c crc.c

INCLUDE := -I ../inc -I ../../ -I $(ICE_APP_INCLUDE_PATH)

CFLAGS += -c -Wall -Wstrict-prototypes -DPLATFORM_USE_MISC_API \
		  $(ICE_APP_CFLAGS) $(INCLUDE) 

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
	@mv $(LIB) $(ICE_LIB_DEST_PATH)/ 

clean:
	@echo "Cleaning library " $(LIB)
	@rm -rf *.o $(ICE_LIB_DEST_PATH)/$(LIB)
