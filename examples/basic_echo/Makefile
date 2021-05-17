.PHONY: shared clean

APP = basic_echo
DEBUG ?= 1

ifeq ($(PV_HOME),)
PV_HOME = $(word 1, $(subst /examples, , $(realpath $(lastword $(MAKEFILE_LIST)))))
endif

ifeq ($(DEBUG), 1)
	CFLAGS=-Wl,-rpath=$(PV_HOME)/libpv -O0 -g -fsanitize=address
else
	CFLAGS=-Wl,-rpath=$(PV_HOME)/libpv -O3
endif

SRCS := main.c

all: shared

shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
	cp build/$(APP) $(APP)

PKGCONF ?= pkg-config

LDFLAGS_SHARED = -L $(PV_HOME)/libpv -lpv
INCLUDE = -I $(PV_HOME)/libpv/include


build/$(APP)-shared: $(SRCS) | build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(INCLUDE) $(LDFLAGS) $(LDFLAGS_SHARED)

build:
	@mkdir -p $@

clean:
	rm -rf build
	rm -f $(APP)

