#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <algorithm>
#include <iomanip>


using namespace std;
using namespace chrono;

enum AlgorithmType{
        DES,
	TDES,
        AES128,
        AES192,
        AES256,

};

struct TestConfig {

        AlgorithmType algorithm;

        size_t dataSize;
        double encryptionTime;
        double decryptionTime;
        double throughput;

};

vector <unsigned char> generateRandomData(size_t size){

        vector<unsigned char> data(size);
        RAND_bytes(data.data(), size);
        return data;


}

vector<unsigned char> generateKey(AlgorithmType algo){

        vector<unsigned char> key;

        switch(algo){
                case DES:
                        key.resize(8);
                        RAND_bytes(key.data(), 8);
                        break;

                case TDES:
                        key.resize(24);
                        RAND_bytes(key.data(), 24);
                        break;

                case AES128:
                        key.resize(16);
                        RAND_bytes(key.data(), 16);
                        break;

                case AES192:
                        key.resize(24);
                        RAND_bytes(key.data(), 24);
                        break;

                case AES256:
                        key.resize(32);
                        RAND_bytes(key.data(), 32);
                        break;
        }

        return key;
}

const EVP_CIPHER* getCipher(AlgorithmType algo){

	switch(algo){
	
		case DES:
			return EVP_des_cbc();

		case TDES:
			return EVP_des_ede3_cbc();

		case AES128:
			return EVP_aes_128_cbc();

		case AES192:
			return EVP_aes_192_cbc();

		case AES256:
			return EVP_aes_256_cbc();

		default:
			return EVP_aes_256_cbc();

	}

}

TestConfig tester(size_t dataSize, AlgorithmType algo){

	TestConfig config;
	config.algorithm = algo;
	config.dataSize = dataSize;

	vector<unsigned char> plaintext = generateRandomData(dataSize);
	vector<unsigned char> key = generateKey(algo);

	const EVP_CIPHER* cipher = getCipher(algo);

	vector<unsigned char> iv(EVP_CIPHER_iv_length(cipher));
	RAND_bytes(iv.data(), iv.size());

	EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(context, cipher, NULL, key.data(), iv.data());

	EVP_CIPHER_CTX_set_padding(context, 1);

	size_t ciphertext_len = plaintext.size() + EVP_CIPHER_block_size(cipher);
	vector<unsigned char> ciphertext(ciphertext_len);

	int len = 0;

	auto start = high_resolution_clock::now();

	EVP_EncryptUpdate(context, ciphertext.data(), &len, plaintext.data(), plaintext.size());

	int cipher_len = len;

	EVP_EncryptFinal_ex(context, ciphertext.data() + len, &len);
	cipher_len += len;

	auto end = high_resolution_clock::now();

	config.encryptionTime = duration<double>(end - start).count();

	ciphertext.resize(cipher_len);

	EVP_CIPHER_CTX_reset(context);

	EVP_DecryptInit_ex(context, cipher, NULL, key.data(), iv.data());

	EVP_CIPHER_CTX_set_padding(context, 1);

	vector<unsigned char> decrypted(ciphertext.size() + EVP_CIPHER_block_size(cipher));

	start = high_resolution_clock::now();

	EVP_EncryptUpdate(context, decrypted.data(), &len, ciphertext.data(), ciphertext.size());

	int plaintext_len = len;

	EVP_DecryptFinal_ex(context, decrypted.data() + len, &len);
	plaintext_len += len;

	end = high_resolution_clock::now();

	config.decryptionTime = duration<double>(end - start).count();

	decrypted.resize(plaintext_len);

	EVP_CIPHER_CTX_free(context);

	config.throughput = (dataSize / (1024.0 * 1024.0)) / config.encryptionTime;

	if (config.encryptionTime > 0) {
       		config.throughput = (dataSize / (1024.0 * 1024.0)) / config.encryptionTime;
    	} else {
        	config.throughput = 0;
   	}
	


	return config;


}

        
void printResults(const vector<TestConfig>& results){
	cout << "\nAlgorithm,Data Size (MB), Encryption Time (s), Decryption Time (s), Throughput (MB/s) \n";

	for ( const auto& result : results){
		string algoName;
		switch(result.algorithm) {
			case DES:
				algoName = "DES";
				break;

			case TDES:
				algoName = "3DES";
				break;

			case AES128:
				algoName = "AES-128";
				break;

			case AES192:
				algoName = "AES-192";
				break;

			case AES256: 
				algoName = "AES-256";
				break;

		}
		
		double dataSizeMB = result.dataSize / (1024.0 * 1024.0);

		cout << algoName << "," << dataSizeMB << "," << fixed << setprecision(6) << result.encryptionTime << "," << result.decryptionTime << "," << result.throughput << "\n";

	}

}	


int main(){

	RAND_poll();
	OpenSSL_add_all_algorithms();


	vector<size_t> dataSize = {
		1 * 1024 * 1024,
		10 * 1024 * 1024,
		100 * 1024 * 1024,
		500 * 1024 * 1024,
		1 * 1024 * 1024 * 1024

	};

	vector<TestConfig> results;

	cout << " Test data sizes: 1MB, 10MB, 100MB, 500MB, 1GB \n\n";

	vector<AlgorithmType> algorithm = {DES, TDES, AES128, AES192, AES256};

	for (size_t size : dataSize) {
        	cout << "Testing with " << size/(1024*1024) << " MB data...\n";
		for(AlgorithmType algo : algorithm){

			string algoName;
			switch(algo){
			
				case DES:
					algoName = "DES";
					break;

				case TDES:
					algoName = "3DES";
					break;

				case AES128:
					algoName = "AES-128";
					break;

				case AES192:
					algoName = "AES-192";
					break;

				case AES256:
					algoName = "AES-256";
					break;

			}
			cout << "Testing " << algoName << ". . .";
			results.push_back(tester(size,algo));
			cout << " done\n";
		}
   	}
	printResults(results);


	EVP_cleanup();

	return 0;
	

}
