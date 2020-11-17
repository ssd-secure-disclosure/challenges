.PHONY: all clean
CCFLAGS=-std=c++11 -s -Os
OUT_DIR=$(PWD)/build/
all: out_dir bevx_cha1
bevx_lib.so: bevx_lib.o
        g++ -shared -o build/bevx_lib.so build/bevx_lib.o
bevx_lib.o: out_dir bevx_lib.cpp
        g++ $(CCFLAGS) -fPIC -c bevx_lib.cpp -o build/bevx_lib.o
bevx_cha1: bevx_cha1.cpp bevx_lib.so
        g++ -o build/bevx_cha1 $(CCFLAGS) bevx_cha1.cpp -L$(OUT_DIR) -l:./bevx_lib.so -lstdc++
out_dir:
        mkdir -p $(OUT_DIR)
clean:
        rm -rf build/
