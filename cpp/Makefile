CXX      ?= g++
CXXFLAGS ?= -Wall -Wextra -O2 -std=c++17
BUILD    := build

.PHONY: all clean

all: $(BUILD)/sentinel-log-analyzer

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sentinel-log-analyzer: log_analyzer.cpp log_analyzer.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) log_analyzer.cpp -o $@

clean:
	rm -rf $(BUILD)
