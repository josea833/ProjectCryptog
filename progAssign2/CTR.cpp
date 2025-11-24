#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <iomanip>
#include <chrono>

using namespace std;

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8

string aes_CTRCipher(string key, string message);
string des_CTRCipher(string key, string message);
string des3_CTRCipher(string key, string message);
static void hex_print(const void *pv, size_t len);

int main(int argc, char *argv[]) {
    // AES CTR Mode Tests
    cout << "======== AES CTR MODE ========" << endl;
    cout << "\n--- Test Case 1: 128-bit key, short message ---" << endl;
    aes_CTRCipher("0123456789abcdef", "Short message.");
    cout << "\n--- Test Case 2: 256-bit key, longer message ---" << endl;
    aes_CTRCipher("0123456789abcdef0123456789abcdef", "This is a somewhat longer message to test the CTR mode encryption.");
    cout << "\n--- Test Case 3: 192-bit key, message with padding length ---" << endl;
    aes_CTRCipher("0123456789abcdef01234567", "Message of 24 ch");
    
    // DES CTR Mode Tests
    cout << "\n\n======== DES CTR MODE ========" << endl;
    cout << "\n--- Test Case 1: 8-byte key, short message ---" << endl;
    des_CTRCipher("01234567", "Short message.");
    cout << "\n--- Test Case 2: 8-byte key, longer message ---" << endl;
    des_CTRCipher("abcdefgh", "This is a longer message to test DES CTR mode.");
    
    // 3DES CTR Mode Tests
    cout << "\n\n======== 3DES CTR MODE ========" << endl;
    cout << "\n--- Test Case 1: 16-byte key (2-key 3DES), short message ---" << endl;
    des3_CTRCipher("0123456789abcdef", "Short message.");
    cout << "\n--- Test Case 2: 24-byte key (3-key 3DES), longer message ---" << endl;
    des3_CTRCipher("0123456789abcdef01234567", "This is a longer message to test 3DES CTR mode encryption.");
    
    return 0;
}

static void hex_print(const void *pv, size_t len) {
    const unsigned char *p = (const unsigned char *)pv;
    if (pv == NULL) {
        printf("NULL\n");
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", p[i]);
    }
    printf("\n");
}

string aes_CTRCipher(string key, string message) {
    cout << "Using AES CTR Mode" << endl;
    size_t key_len_bytes = key.length();
    if (key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32) {
        cerr << "Error: Invalid key length. Must be 16, 24, or 32 bytes, but got " << key_len_bytes << endl;
        return "";
    }

    size_t inputlength = message.length();
    vector<unsigned char> aes_key(key.begin(), key.end());
    unsigned char *aes_input = new unsigned char[inputlength];
    memcpy(aes_input, message.data(), inputlength);

    printf("Input length: %zu bytes\n", inputlength);
    printf("Key length: %zu bytes\n", key_len_bytes);

    // For demonstration only: zero IV. In real applications use a random nonce/IV.
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, inputlength);
    memset(dec_out, 0, inputlength);

    AES_KEY ctr_key;
    AES_set_encrypt_key(aes_key.data(), key_len_bytes * 8, &ctr_key);

    // Manual CTR implementation using AES_encrypt to produce keystream blocks.
    // Counter starts at IV, increments by 1 per block (big-endian increment).
    unsigned char counter[AES_BLOCK_SIZE];
    memcpy(counter, iv, AES_BLOCK_SIZE);
    unsigned char keystream[AES_BLOCK_SIZE];

    size_t offset = 0;
    unsigned long long blockCounter = 0; // 64-bit counter portion
    
    auto start_encrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        // Prepare counter block: IV (first 8 bytes) + counter (last 8 bytes big-endian)
        // Here we keep first 8 bytes of IV constant, use last 8 bytes for counter.
        for (int i = 0; i < 8; ++i) {
            counter[15 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        AES_encrypt(counter, keystream, &ctr_key);
        size_t blockSize = std::min((size_t)AES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = aes_input[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_encrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> encrypt_time = end_encrypt - start_encrypt;


    // Decrypt (same operation): regenerate keystream and XOR.
    memcpy(counter, iv, AES_BLOCK_SIZE);
    blockCounter = 0;
    offset = 0;
    auto start_decrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        for (int i = 0; i < 8; ++i) {
            counter[15 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        AES_encrypt(counter, keystream, &ctr_key);
        size_t blockSize = std::min((size_t)AES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_decrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    printf("Original:\t");
    hex_print(aes_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << encrypt_time.count() << " microseconds" << endl;
    cout << "Decryption time: " << decrypt_time.count() << " microseconds" << endl;

    if (memcmp(aes_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
        printf("Expected: ");
        hex_print(aes_input, inputlength);
        printf("Got: ");
        hex_print(dec_out, inputlength);
    }

    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < inputlength; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    delete[] aes_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}

string des_CTRCipher(string key, string message) {
    cout << "Using DES CTR Mode" << endl;
    size_t key_len_bytes = key.length();
    if (key_len_bytes != 8) {
        cerr << "Error: Invalid key length for DES. Must be 8 bytes, but got " << key_len_bytes << endl;
        return "";
    }

    size_t inputlength = message.length();
    unsigned char *des_input = new unsigned char[inputlength];
    memcpy(des_input, message.data(), inputlength);

    printf("Input length: %zu bytes\n", inputlength);
    printf("Key length: %zu bytes\n", key_len_bytes);

    // Setup DES key
    DES_cblock des_key;
    memcpy(des_key, key.data(), 8);
    DES_key_schedule key_schedule;
    DES_set_key_unchecked(&des_key, &key_schedule);

    // For demonstration: zero IV/counter
    unsigned char counter[DES_BLOCK_SIZE];
    memset(counter, 0x00, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, inputlength);
    memset(dec_out, 0, inputlength);

    size_t offset = 0;
    unsigned long long blockCounter = 0;
    
    auto start_encrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        // Prepare counter block (64-bit counter)
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        DES_ecb_encrypt((DES_cblock *)counter, (DES_cblock *)keystream, &key_schedule, DES_ENCRYPT);
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des_input[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_encrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decrypt (same operation)
    blockCounter = 0;
    offset = 0;
    auto start_decrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        DES_ecb_encrypt((DES_cblock *)counter, (DES_cblock *)keystream, &key_schedule, DES_ENCRYPT);
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_decrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    printf("Original:\t");
    hex_print(des_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << encrypt_time.count() << " microseconds" << endl;
    cout << "Decryption time: " << decrypt_time.count() << " microseconds" << endl;

    if (memcmp(des_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }

    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < inputlength; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    delete[] des_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}

string des3_CTRCipher(string key, string message) {
    cout << "Using 3DES CTR Mode" << endl;
    size_t key_len_bytes = key.length();
    if (key_len_bytes != 16 && key_len_bytes != 24) {
        cerr << "Error: Invalid key length for 3DES. Must be 16 or 24 bytes, but got " << key_len_bytes << endl;
        return "";
    }

    size_t inputlength = message.length();
    unsigned char *des3_input = new unsigned char[inputlength];
    memcpy(des3_input, message.data(), inputlength);

    printf("Input length: %zu bytes\n", inputlength);
    printf("Key length: %zu bytes\n", key_len_bytes);

    // Setup 3DES keys
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock key1, key2, key3;
    
    memcpy(key1, key.data(), 8);
    memcpy(key2, key.data() + 8, 8);
    if (key_len_bytes == 24) {
        memcpy(key3, key.data() + 16, 8);
    } else {
        // For 2-key 3DES (16 bytes), use key1 as key3
        memcpy(key3, key.data(), 8);
    }
    
    DES_set_key_unchecked(&key1, &ks1);
    DES_set_key_unchecked(&key2, &ks2);
    DES_set_key_unchecked(&key3, &ks3);

    // For demonstration: zero IV/counter
    unsigned char counter[DES_BLOCK_SIZE];
    memset(counter, 0x00, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, inputlength);
    memset(dec_out, 0, inputlength);

    size_t offset = 0;
    unsigned long long blockCounter = 0;
    
    auto start_encrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        // Prepare counter block (64-bit counter)
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        // 3DES encryption of counter: Encrypt with k1, Decrypt with k2, Encrypt with k3
        DES_ecb3_encrypt((DES_cblock *)counter, (DES_cblock *)keystream, &ks1, &ks2, &ks3, DES_ENCRYPT);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des3_input[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_encrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decrypt (same operation)
    blockCounter = 0;
    offset = 0;
    auto start_decrypt = chrono::high_resolution_clock::now();
    while (offset < inputlength) {
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        DES_ecb3_encrypt((DES_cblock *)counter, (DES_cblock *)keystream, &ks1, &ks2, &ks3, DES_ENCRYPT);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    auto end_decrypt = chrono::high_resolution_clock::now();
    chrono::duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    printf("Original:\t");
    hex_print(des3_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << encrypt_time.count() << " microseconds" << endl;
    cout << "Decryption time: " << decrypt_time.count() << " microseconds" << endl;

    if (memcmp(des3_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }

    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < inputlength; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    delete[] des3_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}
