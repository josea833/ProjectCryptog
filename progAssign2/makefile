all: CBC2 CTR

CBC2: CBC2.cpp
	g++ -o CBC2 CBC2.cpp -lcrypto

CTR: CTR.cpp
	g++ -o CTR CTR.cpp -lcrypto

run_cbc: CBC2
	./CBC2

run_ctr: CTR
	./CTR

clean:
	rm -f CBC2 CTR
	rm -f *.o

