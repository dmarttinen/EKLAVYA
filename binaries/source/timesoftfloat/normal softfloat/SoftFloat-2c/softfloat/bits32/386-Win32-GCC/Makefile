
PROCESSOR_H = ../../../processors/386-GCC.h
SOFTFLOAT_MACROS = ../softfloat-macros

OBJ = .o
EXE = .exe
INCLUDES = -I. -I..
COMPILE_C = /mnt/c/Users/andyc/Desktop/build/bin/clang -g -c -o $@ -O2 -mllvm -sub
LINK = /mnt/c/Users/andyc/Desktop/build/bin/clang -g -o $@ -mllvm -sub

ALL: softfloat$(OBJ) timesoftfloat$(EXE)

milieu.h: $(PROCESSOR_H)
	touch milieu.h

softfloat$(OBJ): milieu.h softfloat.h softfloat-specialize $(SOFTFLOAT_MACROS) ../softfloat.c
	$(COMPILE_C) ../softfloat.c

timesoftfloat$(OBJ): milieu.h softfloat.h ../timesoftfloat.c
	$(COMPILE_C) ../timesoftfloat.c

timesoftfloat$(EXE): softfloat$(OBJ) timesoftfloat$(OBJ)
	$(LINK) softfloat$(OBJ) timesoftfloat$(OBJ)

