# ---------------------------------------------------------------------------
#  rsa-toolkit — build harness (no external dependencies)
#
#  Targets:
#    make            build the rsa-cli binary           -> build/rsa-cli
#    make test       build and run the unit/KAT tests
#    make attacks    build the offensive attack demos   -> build/attacks/*
#    make asan       build + run tests under ASan/UBSan
#    make clean      remove the build directory
# ---------------------------------------------------------------------------

CXX      ?= c++
CXXSTD   ?= -std=c++17
OPT      ?= -O2
WARN     ?= -Wall -Wextra
INCLUDES := -Iinclude
CXXFLAGS ?= $(CXXSTD) $(OPT) $(WARN) $(INCLUDES)

BUILD    := build
OBJ      := $(BUILD)/obj

# Core cryptographic library (no console / file-IO code)
LIB_SRCS := $(wildcard src/*.cpp)
LIB_OBJS := $(patsubst src/%.cpp,$(OBJ)/%.o,$(LIB_SRCS))

# Interactive application layer (console UI, file handling, self-test)
APP_SRCS := $(wildcard src/app/*.cpp)
APP_OBJS := $(patsubst src/app/%.cpp,$(OBJ)/app/%.o,$(APP_SRCS))

TEST_SRCS    := $(wildcard tests/*.cpp)
TEST_BINS    := $(patsubst tests/%.cpp,$(BUILD)/tests/%,$(TEST_SRCS))
ATTACK_SRCS  := $(wildcard attacks/*.cpp)
ATTACK_BINS  := $(patsubst attacks/%.cpp,$(BUILD)/attacks/%,$(ATTACK_SRCS))

.PHONY: all cli test attacks asan clean

all: cli

cli: $(BUILD)/rsa-cli

$(BUILD)/rsa-cli: $(LIB_OBJS) $(APP_OBJS) apps/cli.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(LIB_OBJS) $(APP_OBJS) apps/cli.cpp -o $@

$(OBJ)/%.o: src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ)/app/%.o: src/app/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- tests -----------------------------------------------------------------
test: $(TEST_BINS)
	@echo "================ running tests ================"
	@fail=0; for t in $(TEST_BINS); do \
		echo "--- $$t ---"; \
		$$t || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi

$(BUILD)/tests/%: tests/%.cpp $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $< $(LIB_OBJS) -o $@

# --- attack demos ----------------------------------------------------------
attacks: $(ATTACK_BINS)

$(BUILD)/attacks/%: attacks/%.cpp $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $< $(LIB_OBJS) -o $@

# --- sanitizer build -------------------------------------------------------
asan:
	$(MAKE) clean
	$(MAKE) test OPT="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -rf $(BUILD)
