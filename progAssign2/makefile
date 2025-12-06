all: CBC2 CTR CTR_HighLevel OFB OFB_HighLevel

CBC2: CBC2.cpp
	g++ -o CBC2 CBC2.cpp -lcrypto

CTR: CTR.cpp
	g++ -o CTR CTR.cpp -lcrypto

CTR_HighLevel: CTR_HighLevel.cpp
	g++ -o CTR_HighLevel CTR_HighLevel.cpp -lcrypto

OFB: OFB.cpp
	g++ -o OFB OFB.cpp -lcrypto

OFB_HighLevel: OFB_HighLevel.cpp
	g++ -o OFB_HighLevel OFB_HighLevel.cpp -lcrypto

run_cbc: CBC2
	./CBC2

run_ctr: CTR
	./CTR

run_ctr_highlevel: CTR_HighLevel
	./CTR_HighLevel

run_ofb: OFB
	./OFB

run_ofb_highlevel: OFB_HighLevel
	./OFB_HighLevel

clean:
	rm -f CBC2 CTR CTR_HighLevel OFB OFB_HighLevel
	rm -f *.o

