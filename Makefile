CC=g++
LIBS=-lcrypto -lsecp256k1 -lpthread

all:
	$(CC) -o plutus++ plutus++.cpp $(LIBS)

public:
	mkdir build | true
	$(CC) -o build/plutus++ plutus++.cpp $(LIBS)
	chmod +x build/plutus++
	cp compact.txt build/compact.txt
	printf "USAGE: \`./plutus++ <addressList file> <rounds>\`\n\nEx: \`./plutus++ compact.txt 8192\`" > build/README.md

clean:
	rm -rf build