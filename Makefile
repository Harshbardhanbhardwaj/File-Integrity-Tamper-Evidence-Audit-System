# File Integrity & Tamper-Evidence Audit System - top-level Makefile
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
CPPFLAGS += -Iinclude -Idriver
LDLIBS   += -pthread

SRC_LIB := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
OBJ_LIB := $(SRC_LIB:src/%.cpp=build/%.o)
TEST_SRC := $(wildcard tests/*.cpp)
TEST_OBJ := $(TEST_SRC:tests/%.cpp=build/tests_%.o)

.PHONY: all test integration check-all asan driver clean docs-zip

all: bin/fiaudit

bin/fiaudit: $(OBJ_LIB) build/main.o | bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

bin/run_tests: $(OBJ_LIB) $(TEST_OBJ) | bin
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

build/%.o: src/%.cpp | build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -c $< -o $@

build/tests_%.o: tests/%.cpp | build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -c $< -o $@

bin build:
	mkdir -p $@

test: bin/run_tests
	./bin/run_tests

integration: bin/fiaudit
	bash tests/integration_test.sh

check-all: test integration

# Rebuild everything with AddressSanitizer + UBSan and run the tests
asan:
	$(MAKE) clean
	$(MAKE) CXXFLAGS="-std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra" bin/run_tests bin/fiaudit
	./bin/run_tests

# Kernel module (needs linux-headers); not part of 'all'
driver:
	$(MAKE) -C driver

clean:
	rm -rf build bin
	-$(MAKE) -C driver clean 2>/dev/null || true

-include $(wildcard build/*.d)
