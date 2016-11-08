SHELL := /bin/bash
cJSON ?= lib/cJSON
LIBLITMUS ?= /media/litmus/liblitmus
INSTALL_TARGET ?= /etc/init.d


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
TARGET			= litrosd

ifeq (${CC},cc)
CC = gcc
endif

.PHONY: clean all install

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(LDLIBS) $(LDFLAGS) 

all: cjson $(TARGET)

cjson:
	$(MAKE) -C ${cJSON}
	$(MAKE) -C ${cJSON} install

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LDLIBS) $(LDFLAGS)

clean:
	$(MAKE) -C ${cJSON} clean
	rm $(TARGET) *.o

install: $(TARGET)
	@if [ -f $(TARGET) ]; \
	then \
		source .config; \
		if [ ! -d ${LITROS_DEFAULT_DIR} ]; \
			then \
			echo "Creating configuration folder ${LITROS_DEFAULT_DIR}"; \
			mkdir ${LITROS_DEFAULT_DIR}; \
			echo "Creating config file ${LITROS_CONFIG_TARGET}"; \
			echo "#!/usr/bin/env bash">${LITROS_CONFIG_TARGET}; \
			echo "rt_folder=\"${LITROS_DEFAULT_CONFIG_DIR}\"">>${LITROS_CONFIG_TARGET}; \
			echo "Creating default rt_config folder ${LITROS_DEFAULT_CONFIG_DIR}"; \
			mkdir ${LITROS_DEFAULT_CONFIG_DIR}; \
		fi; \
	else \
		echo "$(TARGET) is not found. Did make complete successively?"; \
	fi;

config-ok  := $(shell test -d "${cJSON}" || echo invalid path. )
ifneq ($(strip $(config-ok)),)
$(info (!!) Could not find cJSON source files at ${cJSON}: ${config-ok})
endif
