# Include the basic Makefile template
include $(shell skull-config --cpp-inc)

# Implicit include .Makefile.inc from top folder if exist
-include $(SKULL_SRCTOP)/.Makefile.inc

INC = \
    $(shell skull-config --includes)

# User ldflags
DEPS_LDFLAGS += \
    $(shell skull-config --ldflags)

# Lib dependencies. Notes: Put skull defaults at the end.
DEPS_LIBS += \
    -lcares \
    -lresolv \
    $(shell skull-config --libs)

# Test lib dependencies. Notes: Put skull defaults at the end.
TEST_DEPS_LIBS += \
    -lcares \
    -lresolv \
    $(shell skull-config --test-libs)

# Objs and deployment related items
SRCS = \
    src/service.cpp \
    src/cache.cpp

TEST_SRCS = \
    tests/test_service.cpp

# valgrind suppresion file
#  note: if the suppresion file is exist, then need to append
#        `--suppressions=$(SUPPRESSION)` to `VALGRIND`
SUPPRESSION := $(GLOBAL_SUPPRESSION)

# valgrind command
VALGRIND ?= valgrind --tool=memcheck --leak-check=full -v \
    --suppressions=$(SUPPRESSION) \
    --gen-suppressions=all --error-exitcode=1

# Include the basic Makefile targets
include $(shell skull-config --cpp-targets)

# Notes: There are some available targets we can use if needed
#
#  prepare - This one is called before compilation
#  check   - This one is called when doing the Unit Test
#  valgrind-check - This one is called when doing the memcheck for the Unit Test
#  deploy  - This one is called when deployment be triggered
#  clean   - This one is called when cleanup be triggered

