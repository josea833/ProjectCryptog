#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <openssl/aes.h>
#include <iomanip>
using namespace std;
#define AES_KEYLENGTH 32
#define AES_BLOCK_SIZE 16
string aes_Cipher(string key, string message);




int main(int argc, char *argv[])
{
    aes_Cipher("1157920892373161954235709850086879078532699846656405640394575838842397763041640", "Hello, how are you, you mad?");
    return 0;
}

static void hex_print(const void *pv, size_t len)
{
    const unsigned char *p = (const unsigned char *)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i < len; i++)
            printf("%02X ", *p++);
    }
    printf("\n");
}



string aes_Cipher(string key, string message)
{
    size_t inputlength = message.length();
    unsigned char aes_key[AES_KEYLENGTH];
    unsigned char *aes_input = new unsigned char[inputlength + 1];
    memset(aes_input, 0, inputlength + 1);
    memset(aes_key, 0, AES_KEYLENGTH);
    strncpy((char *)aes_input, message.c_str(), inputlength);
    string shortened_key = key.substr(0, AES_KEYLENGTH);
    strncpy((char *)aes_key, shortened_key.c_str(), AES_KEYLENGTH);

    printf("Input length: %zu bytes\n", inputlength);
    printf("Key length: %zu bytes (using first %d)\n", key.length(), AES_KEYLENGTH);
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char saved_iv[AES_BLOCK_SIZE];
    // Better: use a random IV for security, but keeping zeros for consistency
    memset(iv, 0x00, AES_BLOCK_SIZE);
    memcpy(saved_iv, iv, AES_BLOCK_SIZE);
    const size_t encslength = ((inputlength + AES_BLOCK_SIZE) /
                               AES_BLOCK_SIZE) *
                              AES_BLOCK_SIZE;
    unsigned char *enc_out = new unsigned char[encslength];
    unsigned char *dec_out = new unsigned char[inputlength];
    memset(enc_out, 0, encslength);
    memset(dec_out, 0, inputlength);
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, AES_KEYLENGTH * 8, &enc_key);
    // unsigned char iv_enc[AES_BLOCK_SIZE];
    // memcpy(iv_enc, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(aes_input, enc_out, inputlength, &enc_key, iv,
                    AES_ENCRYPT);
    AES_set_decrypt_key(aes_key, AES_KEYLENGTH * 8, &dec_key);
    // unsigned char iv_dec[AES_BLOCK_SIZE];
    // memcpy(iv_dec, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key,
                    saved_iv, AES_DECRYPT);
    printf("Orgiginal:\t");
    hex_print(aes_input, inputlength);
    printf("encrypt:\t");
    hex_print(enc_out, encslength);
    printf("Decrypt:\t");
    hex_print(dec_out, inputlength);
    if (memcmp(aes_input, dec_out, inputlength) == 0)
    {
        printf("SUCCESS: Decryption matches original!\n");
    }
    else
    {
        printf("ERROR: Decryption failed!\n");
        printf("Expected: ");
        hex_print(aes_input, inputlength);
        printf("Got: ");
        hex_print(dec_out, inputlength);
    }
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < encslength; i++)
    {
        ss << setw(2) << (int)enc_out[i];
    }
    return ss.str();
}