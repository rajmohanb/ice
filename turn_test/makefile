
# Macros

# executable name
TARGET := turn_test

# source files
SRC :=  test_turn.c

# Include header files
INCLUDE :=-I ../stun/msg_layer/inc -I ../ -I ../stun/parse_format/inc -I ../stun/transaction/inc

# Include library files
LIBRARY := ../stun/msg_layer/lib/stun_msg_layer.a ../stun/parse_format/lib/stun_parse_format.a ../stun/transaction/lib/stun_txn.a ../platform/lib/lib_platform.a -lssl -lm -lrt -ldl

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

# Clean Object files and Executable file
clean:
	@echo "Removing Executable" $(TARGET)
	@rm -rf $(OBJ) $(TARGET)

