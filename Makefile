CFLAGS=-O5 -fomit-frame-pointer -march=native -mtune=native

crackxls2003: pole.cpp extract.cpp -lssl -lgmp -lstdc++

clean:
	rm crackxls2003 *.o


