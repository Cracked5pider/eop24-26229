Name := eop24-26229

##
## compilers
##
CC_X64 := clang++

##
## riscv64 compiler flags
##
RV64FLAGS += --target=riscv64 -march=rv64im -mcmodel=medany
RV64FLAGS += -fno-exceptions -fshort-wchar -Os

##
## compiler flags
##
INCLUDE   += -Iinclude -I../../include
CFLAGS    += $(INCLUDE) -fpermissive -flto -Os -fno-exceptions -Wno-pragma-pack -Wno-microsoft-enum-forward-reference
LLVMFLAGS += -Wl,/mllvm:-lto-embed-bitcode=post-merge-pre-opt -Wl,/entry:main

##
## plugin source and object files
##
FB-SRC := $(wildcard src/*.cc)
FB-OBJ := $(FB-SRC:%.cc=%.obj)

##
## crt0 file and object file
##
CRT0_SRC := ../../lib/crt0.c
CRT0_OBJ := bin/obj/crt0.rv64.obj

##
## x64 binaries
##
ELF_X64	:= bin/$(Name).x64.elf
BIN_X64	:= bin/$(Name).x64.bin

##
## Build kaine source into executable
## and extract shellcode
##
x64: crt0 $(FB-OBJ)
	ld.lld -o $(ELF_X64) --oformat=elf -emit-relocs -T scripts/sections.ld --Map=bin/$(Name).x64.map bin/obj/*.rv64.obj
	@ llvm-objcopy -O binary $(ELF_X64) $(BIN_X64).pre
	@ python scripts/relocs.py $(ELF_X64) --binary $(BIN_X64).pre --output $(BIN_X64)

##
## compile the crt0 for the plugin
##
crt0:
	@ $(CC_X64) $(INCLUDE) -x c $(RV64FLAGS) -c $(CRT0_SRC) -o $(CRT0_OBJ)

##
## Build source to object files
##
$(FB-OBJ):
	$(CC_X64) $(RV64FLAGS) $(INCLUDE) -c $(basename $@).cc -o bin/obj/$(basename $(notdir $@)).rv64.obj

##
## cleanup binaries
##
clean:
	@ rm bin/$(Name).*
	@ rm bin/obj/*
