#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <openssl/evp.h>
#include <iomanip>
#include <chrono>
#include <cstdlib>



using namespace std;
using namespace std::chrono;

#define AES_BLOCK_SIZE 16
#define DES_BLOCK_SIZE 8

string aes_CTRCipher_HighLevel(string key, string message);
string des_CTRCipher_HighLevel(string key, string message);
string des3_CTRCipher_HighLevel(string key, string message);
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
    cout << "CTR MODE ENCRYPTION PERFORMANCE TESTING (HIGH-LEVEL API)" << endl;
    cout << "Testing: DES (64-bit), 3DES (64-bit), AES (128/192/256-bit)" << endl;
    cout << "========================================\n" << endl;
    
    /*
    // ==================== DES CTR MODE (64-bit key) ====================
    cout << "======== DES CTR MODE (64-bit key) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        cout << "\n--- Test Case: 64-bit key, " << size.first << " plaintext ---" << endl;
        des_CTRCipher_HighLevel("01234567", plaintext);
    }
    
    /*
    // ==================== 3DES CTR MODE (64-bit key) ====================
    cout << "\n\n======== 3DES CTR MODE (0123456789abcdef01234567) ========" << endl;
    for (const auto &size : sizes) {
        string plaintext;
        size_t remaining = size.second;
        while (remaining > 0) {
            size_t to_add = min(remaining, plaintext_pattern.length());
            plaintext += plaintext_pattern.substr(0, to_add);
            remaining -= to_add;
        }
        cout << "\n--- Test Case: 3-key 3DES , " << size.first << " plaintext ---" << endl;
        des3_CTRCipher_HighLevel("0123456789abcdef01234567", plaintext);
    }
    */
    // ==================== AES CTR MODE - 128-bit key ====================
    cout << "\n\n======== AES CTR MODE (128-bit key) ========" << endl;
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
        aes_CTRCipher_HighLevel("0123456789abcdef", plaintext);
    }
    
    // ==================== AES CTR MODE - 192-bit key ====================
    cout << "\n\n======== AES CTR MODE (192-bit key) ========" << endl;
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
        aes_CTRCipher_HighLevel("0123456789abcdef01234567", plaintext);
    }
    
    // ==================== AES CTR MODE - 256-bit key ====================
    cout << "\n\n======== AES CTR MODE (256-bit key) ========" << endl;
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
        aes_CTRCipher_HighLevel("0123456789abcdef0123456789abcdef", plaintext);
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

string aes_CTRCipher_HighLevel(string key, string message) {
    cout << "Using AES CTR Mode (High-Level EVP API)" << endl;
    
    size_t key_len_bytes = key.length();
    if (key_len_bytes != 16 && key_len_bytes != 24 && key_len_bytes != 32) {
        cerr << "Error: Invalid key length. Must be 16, 24, or 32 bytes, but got " << key_len_bytes << endl;
        return "";
    }

    size_t inputlength = message.length();
    unsigned char *aes_input = new unsigned char[inputlength];
    memcpy(aes_input, message.data(), inputlength);

    printf("Input length: %zu bytes\n", inputlength);
    printf("Key length: %zu bytes\n", key_len_bytes);

    // Zero IV for demonstration
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength + AES_BLOCK_SIZE];
    unsigned char *dec_out = new unsigned char[inputlength + AES_BLOCK_SIZE];
    memset(enc_out, 0, inputlength + AES_BLOCK_SIZE);
    memset(dec_out, 0, inputlength + AES_BLOCK_SIZE);

    // Select cipher based on key length
    const EVP_CIPHER *cipher = nullptr;
    if (key_len_bytes == 16) {
        cipher = EVP_aes_128_ctr();
    } else if (key_len_bytes == 24) {
        cipher = EVP_aes_192_ctr();
    } else if (key_len_bytes == 32) {
        cipher = EVP_aes_256_ctr();
    }

    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    
    int len;
    int ciphertext_len = 0;
    int plaintext_len = 0;

    // Encryption
    auto start_encrypt = high_resolution_clock::now();
    
    EVP_EncryptInit_ex(ctx_enc, cipher, NULL, (unsigned char*)key.data(), iv);
    EVP_EncryptUpdate(ctx_enc, enc_out, &len, aes_input, inputlength);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx_enc, enc_out + len, &len);
    ciphertext_len += len;
    
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Reset IV for decryption
    memset(iv, 0x00, AES_BLOCK_SIZE);

    // Decryption
    auto start_decrypt = high_resolution_clock::now();
    
    EVP_DecryptInit_ex(ctx_dec, cipher, NULL, (unsigned char*)key.data(), iv);
    EVP_DecryptUpdate(ctx_dec, dec_out, &len, enc_out, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx_dec, dec_out + len, &len);
    plaintext_len += len;
    
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    // Print results
    printf("IV:\t");
    hex_print(iv, AES_BLOCK_SIZE);
    printf("Original:\t");
    hex_print(aes_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, ciphertext_len);
    printf("Decrypt:\t");
    hex_print(dec_out, plaintext_len);

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
    for (int i = 0; i < ciphertext_len; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
    delete[] aes_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}

string des_CTRCipher_HighLevel(string key, string message) {
    cout << "Using DES CTR Mode (High-Level EVP API)" << endl;
    
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

    // Zero IV for demonstration
    unsigned char iv[DES_BLOCK_SIZE];
    memset(iv, 0x00, DES_BLOCK_SIZE);

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength + DES_BLOCK_SIZE];
    unsigned char *dec_out = new unsigned char[inputlength + DES_BLOCK_SIZE];
    memset(enc_out, 0, inputlength + DES_BLOCK_SIZE);
    memset(dec_out, 0, inputlength + DES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    int len;
    int ciphertext_len = inputlength;

    // Manual CTR implementation using EVP_des_ecb
    EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, (unsigned char*)key.data(), NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char counter[DES_BLOCK_SIZE];
    memset(counter, 0x00, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];
    unsigned long long blockCounter = 0;
    size_t offset = 0;

    // Encryption
    auto start_encrypt = high_resolution_clock::now();
    
    while (offset < inputlength) {
        // Prepare counter
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        // Encrypt counter to get keystream
        EVP_EncryptUpdate(ctx, keystream, &len, counter, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des_input[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decryption (same operation)
    blockCounter = 0;
    offset = 0;
    
    auto start_decrypt = high_resolution_clock::now();
    
    while (offset < inputlength) {
        // Prepare counter
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        // Encrypt counter to get keystream
        EVP_EncryptUpdate(ctx, keystream, &len, counter, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    // Print results
    printf("Original:\t");
    hex_print(des_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, ciphertext_len);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << (encrypt_time.count() / 1e6) << " seconds" << endl;
    cout << "Decryption time: " << (decrypt_time.count() / 1e6) << " seconds" << endl;
    double total_time = encrypt_time.count() + decrypt_time.count();
    cout << "Total time: " << (total_time / 1e6) << " seconds" << endl;

    // Verify
    if (memcmp(des_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }

    // Convert to hex string
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < ciphertext_len; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    delete[] des_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}

string des3_CTRCipher_HighLevel(string key, string message) {
    cout << "Using 3DES CTR Mode (High-Level EVP API)" << endl;
    
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

    // Zero IV for demonstration
    unsigned char iv[DES_BLOCK_SIZE];
    memset(iv, 0x00, DES_BLOCK_SIZE);

    // Buffers for encryption/decryption
    unsigned char *enc_out = new unsigned char[inputlength + DES_BLOCK_SIZE];
    unsigned char *dec_out = new unsigned char[inputlength + DES_BLOCK_SIZE];
    memset(enc_out, 0, inputlength + DES_BLOCK_SIZE);
    memset(dec_out, 0, inputlength + DES_BLOCK_SIZE);

    // Select 3DES cipher based on key length
    const EVP_CIPHER *cipher = (key_len_bytes == 24) ? EVP_des_ede3_ecb() : EVP_des_ede_ecb();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    int len;
    int ciphertext_len = inputlength;

    // Manual CTR implementation using EVP_des_ede3_ecb or EVP_des_ede_ecb
    EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char*)key.data(), NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char counter[DES_BLOCK_SIZE];
    memset(counter, 0x00, DES_BLOCK_SIZE);
    unsigned char keystream[DES_BLOCK_SIZE];
    unsigned long long blockCounter = 0;
    size_t offset = 0;

    // Encryption
    auto start_encrypt = high_resolution_clock::now();
    
    while (offset < inputlength) {
        // Prepare counter
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        // Encrypt counter to get keystream
        EVP_EncryptUpdate(ctx, keystream, &len, counter, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            enc_out[offset + i] = des3_input[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    
    auto end_encrypt = high_resolution_clock::now();
    duration<double, micro> encrypt_time = end_encrypt - start_encrypt;

    // Decryption (same operation)
    blockCounter = 0;
    offset = 0;
    
    auto start_decrypt = high_resolution_clock::now();
    
    while (offset < inputlength) {
        // Prepare counter
        for (int i = 0; i < 8; ++i) {
            counter[7 - i] = (unsigned char)((blockCounter >> (8 * i)) & 0xFF);
        }
        // Encrypt counter to get keystream
        EVP_EncryptUpdate(ctx, keystream, &len, counter, DES_BLOCK_SIZE);
        
        size_t blockSize = std::min((size_t)DES_BLOCK_SIZE, inputlength - offset);
        for (size_t i = 0; i < blockSize; ++i) {
            dec_out[offset + i] = enc_out[offset + i] ^ keystream[i];
        }
        blockCounter++;
        offset += blockSize;
    }
    
    auto end_decrypt = high_resolution_clock::now();
    duration<double, micro> decrypt_time = end_decrypt - start_decrypt;

    // Print results
    printf("Original:\t");
    hex_print(des3_input, inputlength);
    printf("Encrypt:\t");
    hex_print(enc_out, ciphertext_len);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);

    cout << "Encryption time: " << (encrypt_time.count() / 1e6) << " seconds" << endl;
    cout << "Decryption time: " << (decrypt_time.count() / 1e6) << " seconds" << endl;
    double total_time = encrypt_time.count() + decrypt_time.count();
    cout << "Total time: " << (total_time / 1e6) << " seconds" << endl;

    // Verify
    if (memcmp(des3_input, dec_out, inputlength) == 0) {
        printf("SUCCESS: Decryption matches original!\n");
    } else {
        printf("ERROR: Decryption failed!\n");
    }

    // Convert to hex string
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < ciphertext_len; ++i) {
        ss << setw(2) << (int)enc_out[i];
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    delete[] des3_input;
    delete[] enc_out;
    delete[] dec_out;

    return ss.str();
}
