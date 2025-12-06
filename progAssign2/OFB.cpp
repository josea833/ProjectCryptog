#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <iomanip>
#include <chrono>
#include <cstdlib>

using namespace std;
using namespace std::chrono;

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8

string aes_OFBCipher(string key, string message);
string des_OFBCipher(string key, string message);
string des3_OFBCipher(string key, string message);
static void hex_print(const void *pv, size_t len);

int main(int argc, char *argv[]) {
    // Define plaintext sizes
    vector<pair<string, size_t>> sizes = {
        {"1MB", 1024UL * 1024},
        {"10MB", 10UL * 1024 * 1024},
        {"100MB", 100UL * 1024 * 1024},
        {"500MB", 500UL * 1024 * 1024},
        {"1GB", 1024UL * 1024 * 1024}
    };
    
    // Generate plaintext data (repeating pattern for consistency)
    string plaintext_pattern = "The quick brown fox jumps over the lazy dog. ";
    
    cout << "========================================" << endl;
    cout << "OFB MODE ENCRYPTION PERFORMANCE TESTING" << endl;
    cout << "Testing: DES (64-bit), 3DES (64-bit), AES (128/192/256-bit)" << endl;
    cout << "========================================\n" << endl;
    
    // ==================== DES OFB MODE (64-bit key) ====================
    cout << "======== DES OFB MODE (64-bit key) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        cout << "\n--- Test Case: 64-bit key, " << size.first << " plaintext ---" << endl;
        des_OFBCipher("01234567", plaintext);
    }
    
    // ==================== 3DES OFB MODE (64-bit key) ====================
    cout << "\n\n======== 3DES OFB MODE (0123456789abcdef01234567) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        cout << "\n--- Test Case: 3-key 3DES , " << size.first << " plaintext ---" << endl;
        des3_OFBCipher("0123456789abcdef01234567", plaintext);
    }
    // ==================== AES OFB MODE - 128-bit key ====================
    cout << "\n\n======== AES OFB MODE (128-bit key) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        plaintext.resize(size.second); // Ensure exact size
        cout << "\n--- Test Case: 128-bit key, " << size.first << " plaintext ---" << endl;
        aes_OFBCipher("0123456789abcdef", plaintext);
    }
    
    // ==================== AES OFB MODE - 192-bit key ====================
    cout << "\n\n======== AES OFB MODE (192-bit key) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        plaintext.resize(size.second); // Ensure exact size
        cout << "\n--- Test Case: 192-bit key, " << size.first << " plaintext ---" << endl;
        aes_OFBCipher("0123456789abcdef01234567", plaintext);
    }
    
    // ==================== AES OFB MODE - 256-bit key ====================
    cout << "\n\n======== AES OFB MODE (256-bit key) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        plaintext.resize(size.second); // Ensure exact size
        cout << "\n--- Test Case: 256-bit key, " << size.first << " plaintext ---" << endl;
        aes_OFBCipher("0123456789abcdef0123456789abcdef", plaintext);
    }
        
    
    return 0;
}

static void hex_print(const void *pv, size_t len) {
    const unsigned char *p = (const unsigned char *)pv;
    if (pv == NULL) {
        printf("NULL\n");
        return;
    }
    
    // For large data, print only first and last 5 bytes
    if (len > 100) {
        // Print first 5 bytes
        for (size_t i = 0; i < 5; ++i) {
            printf("%02X ", p[i]);
        }
        printf("... ");
        // Print last 5 bytes
        for (size_t i = len - 5; i < len; ++i) {
            printf("%02X ", p[i]);
        }
        printf("(total: %zu bytes)\n", len);
    } else {
        // Print all bytes for small data
        for (size_t i = 0; i < len; ++i) {
            printf("%02X ", p[i]);
        }
        printf("\n");
    }
}

string aes_OFBCipher(string key, string message) {
    cout << "Using AES OFB Mode" << endl;
    //get key and message lengths
    size_t key_len_bytes = key.length();
    if (key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32) {
        cerr << "Error: Invalid key length. Must be 16, 24, or 32 bytes, but got " << key_len_bytes << endl;
        return "";
    }

    size_t inputlength = message.length();
    // Prepare key and input buffers
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

    AES_KEY ofb_key;
    AES_set_encrypt_key(aes_key.data(), key_len_bytes * 8, &ofb_key);

    // Manual OFB implementation using AES_encrypt to produce keystream blocks.
    // OFB: Previous encrypted state becomes input to next encryption
    unsigned char state[AES_BLOCK_SIZE];
    memcpy(state, iv, AES_BLOCK_SIZE);
    unsigned char keystream[AES_BLOCK_SIZE];

    size_t offset = 0;
    
    //begin clock
    auto start_encrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        AES_encrypt(state, keystream, &ofb_key);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, AES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)AES_BLOCK_SIZE, inputlength - offset);
        // XOR input block with keystream block, aes_input contains the plaintext or message
        for (size_t i = 0; i < blockSize; ++i) {
            //enc_out is ciphertext
            enc_out[offset + i] = aes_input[offset + i] ^ keystream[i];
        }
        //offset incremented by blocksize
        offset += blockSize;
    }
    //end clock
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;


    // Decrypt (same operation): regenerate keystream and XOR.
    memcpy(state, iv, AES_BLOCK_SIZE);
    offset = 0;

    //begin clock
    auto start_decrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        AES_encrypt(state, keystream, &ofb_key);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, AES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)AES_BLOCK_SIZE, inputlength - offset);
        // XOR ciphertext block with keystream block to get plaintext, enc_out contains the ciphertext
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        //offset incremented by blocksize
        offset += blockSize;
    }
    //end clock
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    //print hex representations of original, encrypted, and decrypted data
    printf("IV:\t");
    hex_print(iv, AES_BLOCK_SIZE);
    printf("Original:\t");
    hex_print(aes_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << (encrypt_time.count() / 1e6) << " seconds" << endl;
    cout << "Decryption time: " << (decrypt_time.count() / 1e6) << " seconds" << endl;
    double total_time = encrypt_time.count() + decrypt_time.count();
    cout << "Total time: " << (total_time / 1e6) << " seconds" << endl;

    // Verify
    if (memcmp(aes_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }

    // Convert to hex string
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < inputlength; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    // Cleanup
    delete[] aes_input;
    delete[] enc_out;
    delete[] dec_out;
    return ss.str();
}

string des_OFBCipher(string key, string message) {
    cout << "Using DES OFB Mode" << endl;
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

    // For demonstration: zero IV
    unsigned char iv[DES_BLOCK_SIZE];
    memset(iv, 0x00, DES_BLOCK_SIZE);
    unsigned char state[DES_BLOCK_SIZE];
    memcpy(state, iv, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, inputlength);
    memset(dec_out, 0, inputlength);

    size_t offset = 0;
    
    auto start_encrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        DES_ecb_encrypt((DES_cblock *)state, (DES_cblock *)keystream, &key_schedule, DES_ENCRYPT);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des_input[offset + i] ^ keystream[i];
        }
        offset += blockSize;
    }
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decrypt (same operation)
    memcpy(state, iv, DES_BLOCK_SIZE);
    offset = 0;
    auto start_decrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        DES_ecb_encrypt((DES_cblock *)state, (DES_cblock *)keystream, &key_schedule, DES_ENCRYPT);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        offset += blockSize;
    }
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    printf("IV:\t");
    hex_print(iv, DES_BLOCK_SIZE);
    printf("Original:\t");
    hex_print(des_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << (encrypt_time.count() / 1e6) << " seconds" << endl;
    cout << "Decryption time: " << (decrypt_time.count() / 1e6) << " seconds" << endl;
    double total_time = encrypt_time.count() + decrypt_time.count();
    cout << "Total time: " << (total_time / 1e6) << " seconds" << endl;

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

string des3_OFBCipher(string key, string message) {
    cout << "Using 3DES OFB Mode" << endl;
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

    // For demonstration: zero IV
    unsigned char iv[DES_BLOCK_SIZE];
    memset(iv, 0x00, DES_BLOCK_SIZE);
    unsigned char state[DES_BLOCK_SIZE];
    memcpy(state, iv, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, inputlength);
    memset(dec_out, 0, inputlength);

    size_t offset = 0;
    
    auto start_encrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        // 3DES encryption of state: Encrypt with k1, Decrypt with k2, Encrypt with k3
        DES_ecb3_encrypt((DES_cblock *)state, (DES_cblock *)keystream, &ks1, &ks2, &ks3, DES_ENCRYPT);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des3_input[offset + i] ^ keystream[i];
        }
        offset += blockSize;
    }
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decrypt (same operation)
    memcpy(state, iv, DES_BLOCK_SIZE);
    offset = 0;
    auto start_decrypt = high_resolution_clock::now();
    while (offset < inputlength) {
        // Encrypt the state to get keystream block
        DES_ecb3_encrypt((DES_cblock *)state, (DES_cblock *)keystream, &ks1, &ks2, &ks3, DES_ENCRYPT);
        // State becomes the keystream for the next iteration (OFB characteristic)
        memcpy(state, keystream, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        offset += blockSize;
    }
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    printf("IV:\t");
    hex_print(iv, DES_BLOCK_SIZE);
    printf("Original:\t");
    hex_print(des3_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, inputlength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << (encrypt_time.count() / 1e6) << " seconds" << endl;
    cout << "Decryption time: " << (decrypt_time.count() / 1e6) << " seconds" << endl;
    double total_time = encrypt_time.count() + decrypt_time.count();
    cout << "Total time: " << (total_time / 1e6) << " seconds" << endl;

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
