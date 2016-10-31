cJSON ?= lib/cJSON
LIBLITMUS ?= /media/litmus/liblitmus


HEADERS			?= -I${cJSON} -I${LIBLITMUS}/include 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include/uapi 
HEADERS			+= -I${LIBLITMUS}/arch/x86/include/generated/uapi

LDFLAGS			= -L${LIBLITMUS}
LDLIBS 			= -llitmus -lcjson -lm -lpthread
CPPFLAGS		= ${HEADERS}
CFLAGS			= -O2 -g -Wall -Wextra -Wshadow -Wdeclaration-after-statement
DEPS			= litros_rt_param.h
OBJ				= litrosd.o litros_rt_param.o

ifeq (${CC},cc)
CC = gcc
endif

.PHONY: clean all

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(LDLIBS) $(LDFLAGS) 

all: cjson litrosd

cjson:
	$(MAKE) -C ${cJSON}
	$(MAKE) -C ${cJSON} install

litrosd: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LDLIBS) $(LDFLAGS)

clean:
	$(MAKE) -C ${cJSON} clean
	rm litrosd *.o

config-ok  := $(shell test -d "${cJSON}" || echo invalid path. )
ifneq ($(strip $(config-ok)),)
$(info (!!) Could not find cJSON source files at ${cJSON}: ${config-ok})
endif


