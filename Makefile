CC=g++
LIBS=-lcrypto -lsecp256k1 -lpthread

all:
	$(CC) -o plutus++ plutus++.cpp $(LIBS)