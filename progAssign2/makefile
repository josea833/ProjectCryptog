all: CBC2 CTR CTR_HighLevel

CBC2: CBC2.cpp
	g++ -o CBC2 CBC2.cpp -lcrypto

CTR: CTR.cpp
	g++ -o CTR CTR.cpp -lcrypto

CTR_HighLevel: CTR_HighLevel.cpp
	g++ -o CTR_HighLevel CTR_HighLevel.cpp -lcrypto

run_cbc: CBC2
	./CBC2

run_ctr: CTR
	./CTR

run_ctr_highlevel: CTR_HighLevel
	./CTR_HighLevel

clean:
	rm -f CBC2 CTR CTR_HighLevel
	rm -f *.o

