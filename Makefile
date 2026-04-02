CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Iinclude
LDFLAGS = -pthread

SRC_DIR = src
BUILD_DIR = build
TARGET = scanner

SOURCES = $(SRC_DIR)/main.cpp $(SRC_DIR)/scanner.cpp $(SRC_DIR)/utils.cpp $(SRC_DIR)/port_database.cpp $(SRC_DIR)/exporter.cpp $(SRC_DIR)/logger.cpp $(SRC_DIR)/config.cpp $(SRC_DIR)/state_manager.cpp $(SRC_DIR)/siem_exporter.cpp $(SRC_DIR)/os_fingerprint.cpp $(SRC_DIR)/nse_engine.cpp
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

.PHONY: all clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
