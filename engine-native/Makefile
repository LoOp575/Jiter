CC      ?= gcc
CXX     ?= g++
CFLAGS  := -std=c11 -O2 -Wall -Wextra -Werror -Ic/include
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror -Ic/include -Icpp/include

BUILD_DIR := build

.PHONY: all test clean

all: $(BUILD_DIR)/test_native_engine

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/jiter_packet.o: c/src/jiter_packet.c c/include/jiter_packet.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/jiter_scheduler.o: cpp/src/jiter_scheduler.cpp cpp/include/jiter_scheduler.hpp cpp/include/jiter_packet_pool.hpp c/include/jiter_packet.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/test_native_engine: tests/test_native_engine.cpp $(BUILD_DIR)/jiter_packet.o $(BUILD_DIR)/jiter_scheduler.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -pthread

test: $(BUILD_DIR)/test_native_engine
	./$(BUILD_DIR)/test_native_engine

clean:
	rm -rf $(BUILD_DIR)
