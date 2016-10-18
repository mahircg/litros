cJSON ?= ../cJSON
LIBLITMUS ?= /media/litmus/liblitmus


HEADERS			?= -I${cJSON} -I${LIBLITMUS}/include 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include/uapi 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include/generated/uapi
#prefix ?= /usr/local

LDFLAGS			= -L${LIBLITMUS}
LDLIBS 			= -llitmus -lcjson -lm
CPPFLAGS		= ${HEADERS}
CFLAGS			= -g -Wall -Wextra -Wdeclaration-after-statement

ifeq (${CC},cc)
CC = gcc
endif

.PHONY: clean all

all: cjson litrosd

cjson:
	$(MAKE) -C ${cJSON}
	$(MAKE) -C ${cJSON} install

litrosd: litros_rt_param.c litrosd.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -c litros_rt_param.c $(LDLIBS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o litrosd litrosd.c $(LDLIBS)

clean:
	$(MAKE) -C ${cJSON} clean
	rm litrosd litros_rt_param.o

config-ok  := $(shell test -d "${cJSON}" || echo invalid path. )
ifneq ($(strip $(config-ok)),)
$(info (!!) Could not find cJSON source files at ${cJSON}: ${config-ok})
endif


