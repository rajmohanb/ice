
# Macros
OG_AGENT := ice_agent_outgoing
IC_AGENT := ice_agent_incoming
OG_AGENT1 := og_agent

# ice sample client 
TARGET := all

# ice sample source files
SRC :=  outgoing_agent.c incoming_agent.c #og_agent.c

# Include header file path
INCLUDE :=-I ../ -I ../ice/inc -I ../turn/inc -I ../stun/msg_layer/inc -I ../ -I ../stun/parse_format/inc -I ../stun/transaction/inc -I ../inc

# library files 
LIBRARY := ../ice/lib/ice_agent_lib.a ../conn_check/lib/conn_check.a ../turn/lib/turn.a ../stun/msg_layer/lib/stun_msg_layer.a ../stun/parse_format/lib/stun_parse_format.a ../stun/transaction/lib/stun_txn.a ../platform/lib/lib_platform.a -lssl -lm -lrt -ldl

CFLAGS += -g -Wall -Wstrict-prototypes -c $(INCLUDE) -DLINUX -DENABLE_TURN
#CFLAGS += -g -Wall -Wstrict-prototypes -fmudflap -c $(INCLUDE) -DLINUX -DENABLE_TURN

OBJ:=$(SRC:c=o)

#
#object Build Rules
#
.c.o :
	@echo [CC] 	$< ...
	$(CC) $(CFLAGS) -o $*.o $<

$(TARGET) : clean $(OBJ)
	@echo "Creating ice client process binary " $(TARGET)
	@$(CC) outgoing_agent.o -o $(OG_AGENT)  $(LIBRARY)
	@$(CC) incoming_agent.o -o $(IC_AGENT)  $(LIBRARY)
	#@$(CC) og_agent.o -o $(OG_AGENT1)  $(LIBRARY)

clean:
	@echo "Removing ice client process binary" $(TARGET)
	@rm -rf $(OBJ) $(OG_AGENT) $(IC_AGENT)

