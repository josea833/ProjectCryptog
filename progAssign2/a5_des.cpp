#include <iostream>
#include <vector>
#include <bitset>
#include <string>
#include <iomanip>
#include <sstream>

using namespace std;

class A51{

private:

        bitset<19> x;
        bitset<22> y;
        bitset<23> z;

        bool majority(){
                int count = (x[8] + y[10] + z[10]);
                return (count >= 2);
        }


        void clock(){



                bool maj = majority();

                if(x[8] == maj){
                        bool j = x[13] ^ x[16]^ x[17] ^ x[18];

                        x << 1;
                        x[0] = j;

                }

                if(y[10] == maj){
                        bool j = y[20] ^ y[21];
                        y <<= 1;
                        y[0] = j;
                }

                if(z[10] == maj){
                        bool j = z[7] ^ z[20] ^ z[21] ^ z[22];
                        z <<= 1;
                        z[0] = j;
                }

        }


public:

        A51(){
                x = bitset<19>("1010010011000011100");
                y = bitset<22>("0011011100100001111011");
                z = bitset<23>("11101010001110111000010");
        }

        bool getKeyStream(){
                clock();

                return x[18] ^ y[21] ^ z[22];
        }

        vector<bool> makeKeyStream(int length){

                vector<bool> keyStream;

                for(int i = 0; i < length; i++){

                        keyStream.push_back(getKeyStream());
                }

                return keyStream;

        }

        string dualFunction( const string& hexText){

                string binary;

                for(char c: hexText){

                        int val;

                        if(c >= '0' && c <= '9'){
                                val = c - '0';
                        }else if ( c >= 'a' && c <= 'f'){
                                val = 10 + c - 'a';
                        }else if( c >= 'A' && c <= 'F'){
                                val = 10 + c - 'A';
                        }else{
                                throw invalid_argument("Invalid Hex");
                        }


                        bitset<4> bits(val);
                        binary += bits.to_string();
                }

                vector<bool> keyStream = makeKeyStream(binary.length());
                string textToBinary;

                for(size_t n = 0; n < binary.length(); n++){

                        textToBinary +=(binary[n] == '1') ^ keyStream[n] ? '1' : '0';

                }

                string textToHex;

                for(size_t h = 0; h < textToBinary.length(); h += 4){
                        string nibble = textToBinary.substr(h, 4);

                        bitset<4> bits(nibble);

                        int val = bits.to_ulong();

                        textToHex += (val < 10) ? ('0' + val) : ('a' + val - 10);

                }


                return textToBinary;

        }


        void print(){


                cout << "X: " << x << endl;
                cout << "Y: " << y << endl;
                cout << "Z: " << z << endl;
        }
};

class des{
private:


        const int IP[64] = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7

        };

        const int FP[64] = {

                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25

        };

        const int DBox[48] = {

                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1

        };

        const int SBox[8][4][16] = {

        {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },


        };

        const int PF[32] = {

                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25

        };

        const int KPC1[56] = {

                57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4

        };

        const int KPC2[48] = {

                14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32


        };

        string hexToBin(const string& hex){

                string bin;

                for(char h: hex){
                        uint8_t n = (h <= '9') ? h - '0' : h - 'a' + 10;
                        bin += bitset<4>(n).to_string();
                }

                return bin;

        }

        const int shiftTable[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

        string binToHex(const string& bin){

                string hex;
             for(size_t i = 0; i < bin.length(); i += 4){
                        string nibble = bin.substr(i, 4);

                        hex += "0123456789abcdef"[bitset<4>(nibble).to_ulong()];
                }

                return hex;

        }

        string permute(const string& text, const int* table, int n){

                string result;

                for(int i = 0; i < n; i++){
                        result += text[table[i] - 1];
                }

                return result;


        }


        string shift_L(const string& key, int shifts){

                string shifted = key.substr(shifts) + key.substr(0, shifts);

                return shifted;

        }


        string xorString (const string& one, const string& two){


                string outcome;

                for(size_t i = 0; i < one.size(); i++){
                        outcome +=(one[i] == two[i]) ? '0' : '1';
                }

                return outcome;
        }


        string usingSbox(const string& text){

                string outcome;

                for(int i = 0; i < 8; i++){
                        string block = text.substr(i * 6, 6);

                        int row = 2 *(block[0] - '0') + (block[5] - '0');
                        int col = 8 *(block[1] - '0') + (block[2] - '0') + 2 * (block[3] - '0') + (block[4] - '0');

                        int val = SBox[i][row][col];

                        outcome += bitset<4>(val).to_string();

                }

                return outcome;

        }



        vector<string> makeSubKey(const string& key){

                string permKey = permute(key, KPC1, 56);
                string left = permKey.substr(0, 28);
                string right = permKey.substr(28, 28);

                vector<string> subKeys;

                for(int i = 0; i < 16; i++){

                        left = shift_L(left, shiftTable[i]);
                        right = shift_L(right, shiftTable[i]);

                        string mix = left + right;
                        string subKey = permute(mix, KPC2, 48);

                        subKeys.push_back(subKey);
                }

                return subKeys;
        }


        string lookThroughBlock(const string&block, const vector<string>& subKeys, bool decrypt = false){

                string perKey = permute(block, IP, 64);
                string left = perKey.substr(0, 32);               string right = perKey.substr(32, 32);

                for(int i = 0; i < 16; i++){

                        string expanded = permute(right, DBox, 48);
                        string xored = xorString(expanded, subKeys[decrypt ? 15 - i: i]);
                        string substitute = usingSbox(xored);
                        string permuted = permute(substitute, PF, 32);
                        string anotherLeft = right;
                        right = xorString(left, permuted);
                        left = anotherLeft;

                }

                string mix = right + left;

                return permute(mix, FP, 64);

        }


public:

        string encryptHex(const string& plaintextHex, const string& hexKey){

                if(hexKey.length() != 16){
                        throw runtime_error("Key must be 16 hex characters(64 bits)");
                }

                string keyBin = hexToBin(hexKey);

                vector<string> subKeys = makeSubKey(keyBin);

                string pad = plaintextHex;

                while(pad.length() % 16 != 0){
                        pad += "0";
                }

                string cipherText;

                for(size_t i = 0;i <  pad.length(); i += 16){
                        string block = pad.substr(i, 16);
                        cipherText += binToHex(lookThroughBlock(hexToBin(block), subKeys));

                }

                return cipherText;

        }



        string decrypt(const string& cipherTextHex, const string& hexKey){
                if(hexKey.length() != 16){
                        throw runtime_error("Key must be 16 hex characters (64 bits)");
                }

                string hexkey = hexToBin(hexKey);

                vector<string> subKeys = makeSubKey(hexkey);

                string plainText;

                for(size_t i = 0; i < cipherTextHex.length(); i += 16){
                        string block = cipherTextHex.substr(i, 16);

                        plainText == binToHex(lookThroughBlock(hexToBin(block), subKeys, true));
                }

                return plainText;

        }


        string expansionFun(const string& input){

                if(input.length() != 32){
                        throw runtime_error("Input must be 32 bits");

                }

                return permute(input,DBox, 48);
        }


        string sBoxSub(const string& input){

                if(input.length() != 48){
                        throw runtime_error("Input must be 48 bits");
                }

                return usingSbox(input);

        }


        string pBoxPerm(const string& input){

                if(input.length() != 32){
                        throw runtime_error("Input must be 32 bits");
                }

                return permute(input, PF, 32);

        }

        vector<string> keySchedule(const string& hexKey){
                if(hexKey.length() != 16){
                      throw runtime_error("Key must be 16 hex Character (64 bits)");
                }

                return makeSubKey(hexToBin(hexKey));
        }

};
void test_A51(){

        cout << " A5/1 Stream Cipher Testing \n";

        A51 cipher;

        vector<bool> keyStream = cipher.makeKeyStream(32);

        cout << "next 32 bits of the keystream: ";

        for(bool bit : keyStream){
                cout << bit;
        }

        cout << "\n \n Register states after 32 bits: \n";
        cipher.print();
        cout <<"\n";

        string message = "7e5d7fff";
        string encryptedText = cipher.dualFunction(message);
        string decrypted = cipher.dualFunction(encryptedText);

        cout << "Original Message: " << message << "\n";
        cout << "Ciphertext: " << encryptedText << "\n";
        cout << "Decrypted Message: " << decrypted << "\n";
        cout << (message == decrypted ? "Successful!" : "Failed!") << "\n\n";



}

void test_DES(){

        cout << " DES Testing \n";

        des desCipher;

        string message = "0123456789abcde";
        string key = "133457799bbcdff1";

        cout << "Test message in hex: " << message << "\n";
        cout << "Test hex key: " << key <<"\n\n";


        vector<string> roundKeys = desCipher.keySchedule(key);

        string cipherText = desCipher.encryptHex(message, key);
        cout << "DES Encryption: " << cipherText << endl;
	
	string binMessage = desCipher.encryptHex(message, key);

	string expand = desCipher.expansionFun(binMessage.substr(0,32));
//	cout << "\n Expansion function: " << expand << endl;
//	cout << "Hex: " << desCipher.binToHex(expand) << endl;
	
	string sbox = desCipher.sBoxSub(expand);
	cout << "\n S-Box output: " << sbox << endl;

	string pbox = desCipher.pBoxPerm(sbox);
	cout << "\n P-Box output: " << pbox << endl;
}

int main (){

        test_A51();
        test_DES();
        return 0;

}

