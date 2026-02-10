CC = g++
CFLAGS = -Wall -Wextra -O2 -std=c++11
LDFLAGS = -lpcap
TARGET = pcap_inject
SOURCES = pcap_inject.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

debug: CFLAGS += -DDEBUG -g
debug: clean $(TARGET)

# For cross-compilation if needed
arm: CC = arm-linux-gnueabi-g++
arm: $(TARGET)

.PHONY: all clean install debug arm