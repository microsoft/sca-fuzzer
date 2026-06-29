CXX      := g++
CXXFLAGS := -O3 -march=native -Wall -Wextra -pedantic -std=c++20

all: leak_detector merger

leak_detector: leak_detector.cpp trace_reader.cpp
	$(CXX) $(CXXFLAGS) -o $@ leak_detector.cpp trace_reader.cpp

merger: merger.cpp
	$(CXX) $(CXXFLAGS) -o $@ merger.cpp

clean:
	rm -f leak_detector merger

.PHONY: all clean
