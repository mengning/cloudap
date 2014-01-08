#
# Makefile for ALL Workspace
#
include ./make.h

TARGETS	 =  agentapd

COMMON_OBJS = rfkill.o netlink.o driver_nl80211.o drivers.o linux_ioctl.o
OBJS = $(COMMON_OBJS) $(COMMON_LIB) $(UTILS_LIB) main.o wiflow_protocol.o

all: $(LIBS) $(TARGETS)

copy:
	$(CP) ../src/drivers/driver.h ./
	$(CP) ../src/drivers/wiflow_protocol.h ./
	$(CP) ../src/drivers/wiflow_protocol.c ./

$(TARGETS):$(OBJS)
	$(CC) $(CC_OUTPUT_FLAGS) $(TARGETS) $(OBJS) $(CC_NETLINK_FLAGS)

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
	$(RM) $(RM_FLAGS) $(OBJS) $(TARGETS)
	$(RM) $(RM_FLAGS) *.lib *.bak *.a *~


