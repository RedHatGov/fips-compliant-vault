SYS_INCL = -I/usr/include -I/usr/include/nss3 -I/usr/include/nspr4
JNI_INCL = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

INCLUDES = -I$(TARGETDIR)/mozilla/jss/dist/private/jss $(SYS_INCL) $(JNI_INCL)
LIBS = -L/usr/lib64 -L$(TARGETDIR)
TARGET_LIB = libnss_pbkdf2.so # target lib

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g $(INCLUDES)
LDFLAGS = -shared $(LIBS) -ljss4
RM = rm -f
 
SRCS = $(shell echo *.c)
 
.PHONY: all
all: ${TARGET_LIB}
 
$(TARGET_LIB): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
 
.PHONY: clean
clean:
	-$(RM) $(TARGET_LIB)
