#
# Makefile for ALL Workspace
#
include ./make.h

TARGETS	 =  agentapd

COMMON_OBJS = rfkill.o netlink.o driver_nl80211.o drivers.o linux_ioctl.o wiflow_protocol.o
OBJS = $(COMMON_OBJS) $(COMMON_LIB) $(UTILS_LIB)

all: $(LIBS) $(TARGETS)

copy:
	$(CP) ../src/drivers/wiflow_protocol.h ./
	$(CP) ../src/drivers/wiflow_protocol.c ./

$(TARGETS):$(OBJS) main.o test.o
	$(CC) $(CC_OUTPUT_FLAGS) $(TARGETS) main.o $(OBJS) $(CC_NETLINK_FLAGS) 
	$(CC) $(CC_OUTPUT_FLAGS) test test.o $(OBJS) $(CC_NETLINK_FLAGS) $(CC_OPENSSL_FLAGS)

.c.o:
	$(CC) $(CC_FLAGS)  $(COMMON_INCLUDE_DIRS)  $<

# Make for utils
$(UTILS_LIB):
	make -w -C $(UTILS_DIR) -f Makefile	all
	$(CP) $(UTILS_DIR)/$(UTILS_LIB) ./

# Make for common
$(COMMON_LIB):
	make -w -C $(COMMON_DIR) -f Makefile	all
	$(CP) $(COMMON_DIR)/$(COMMON_LIB) ./
	
clean:
	make -w -C $(UTILS_DIR) -f Makefile clean
	make -w -C $(COMMON_DIR) -f Makefile clean
	$(RM) $(RM_FLAGS) $(OBJS) $(TARGETS) test test.o
	$(RM) $(RM_FLAGS) *.lib *.bak *.a *~


