//
//  main.cpp
//  AESKeySchedule
//
//  Created by Tebin on 9/24/17.
//  Copyright © 2017 Tebin. All rights reserved.
//

#include <iostream>
#include <string.h>
#include <map>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sstream>

typedef unsigned char byte;

using namespace std;

string key = "2B7E151628AED2A6ABF7158809CF4F3C";
vector<vector<unsigned char>> sbox =
{
//  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76}, //0
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, //1
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15}, //2
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, //3
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84}, //4
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, //5
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8}, //6
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, //7
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73}, //8
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, //9
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79}, //A
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08}, //B
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, //C
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E}, //D
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, //E
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}  //F
};

vector<vector<unsigned char>> rcon =
{
    {0x01,0x00,0x00,0x00},  //RCON[1]
    {0x02,0x00,0x00,0x00},  //RCON[2]
    {0x04,0x00,0x00,0x00},  //RCON[3]
    {0x08,0x00,0x00,0x00},  //RCON[4]
    {0x10,0x00,0x00,0x00},  //RCON[5]
    {0x20,0x00,0x00,0x00},  //RCON[6]
    {0x40,0x00,0x00,0x00},  //RCON[7]
    {0x80,0x00,0x00,0x00},  //RCON[8]
    {0x1B,0x00,0x00,0x00},  //RCON[9]
    {0x36,0x00,0x00,0x00}   //RCON[10]
};

vector<vector<string>> ConvertKeyInto4Groups(string key) {
    vector<vector<string>> dword;
    vector<string> fourBytes;
    int k = 0;
    for (int i=0; i<key.length(); i+=8) {
        //i = 0, 8, 16, 24, 32
        string sub = key.substr(i,8);
        fourBytes.push_back(sub);
        k++;
    }
    for (int i = 0; i<fourBytes.size(); i++) {
        vector<string> eachFour;
        for (int k=0; k<fourBytes[i].length(); k+=2) {
            string eachByte = fourBytes[i].substr(k,2);
            eachFour.push_back(eachByte);
        }
        dword.push_back(eachFour);
    }
    return dword;
}

int ConvertHexLetterToNumber(char hex) {
    int result = 0;
    if (hex == 'A') {
        result = 10;
    }else if (hex == 'B'){
        result = 11;
    }else if (hex == 'C'){
        result = 12;
    }else if (hex == 'D'){
        result = 13;
    }else if (hex == 'E'){
        result = 14;
    }else if (hex == 'F'){
        result = 15;
    }
    return result;
}


vector<vector<int>> GetSubBytePosition(vector<string> last4Bytes) {
    vector<vector<int>> positions;
    for (int i = 0; i < last4Bytes.size(); i++) {
        vector<int> colrow;
        char col = last4Bytes[i][0];
        char row = last4Bytes[i][1];
        
        if (!isdigit(col) && !isdigit(row)) {
            colrow.push_back(ConvertHexLetterToNumber(toupper(col)));
            colrow.push_back(ConvertHexLetterToNumber(toupper(row)));
        }else if (!isdigit(col)) {
            colrow.push_back(ConvertHexLetterToNumber(toupper(col)));
            row = atoi(&row);
            colrow.push_back(toupper(row));
        }else if (!isdigit(row)) {
            col = atoi(&col);
            colrow.push_back(toupper(col));
            colrow.push_back(ConvertHexLetterToNumber(toupper(row)));
        } else {
            col = atoi(&col);
            row = atoi(&row);
            colrow.push_back(toupper(col));
            colrow.push_back(toupper(row));
        }
        
        positions.push_back(colrow);
    }
    return positions;
}
vector<string> DoRotWordOnLast(vector<string> lastfour) {
    auto last4bytes = lastfour;  //
    auto firstByte = last4bytes[0];
    for (int k=0; k < last4bytes.size() - 1; k++) {
        last4bytes[k] = last4bytes[k+1];
    }
    last4bytes[3] = firstByte;
    return last4bytes;
}
vector<unsigned char> SubByte(vector<vector<int>> positions) {
    vector<unsigned char> sboxValues;
    for (int i =0; i<positions.size(); i++) {
            auto row = positions[i][0];
            auto col = positions[i][1];
            sboxValues.push_back(sbox[row][col]);
    }
    return sboxValues;
}
vector<int> StringToInt(vector<string> bytes) {
    vector<int> nums;
    for (int i = 0; i < bytes.size(); i++) {
        string ch0 = bytes[i];
        int num = stoi(ch0, 0, 16);
        nums.push_back(num);
    }
    return nums;
}
vector<int> firstXOR(vector<unsigned char> subyte, vector<unsigned char> rcon, vector<int> firstWord) {
    vector<int> result;
    for (int i =0; i < subyte.size(); i++) {
        int r = subyte[i] ^ rcon[i] ^ firstWord[i];
        result.push_back(r);
    }
    return result;
}
vector<int> generateKey(vector<vector<string>> previousKey, vector<int> lastKeyFirst) {
    vector<int> key = lastKeyFirst;
    vector<int> prev = lastKeyFirst;
    for (int i=1; i<4; i++) {
        vector<int> newKey;
        for (int k=0; k<lastKeyFirst.size(); k++) {
            auto pk = previousKey[i];
            auto convertPk = StringToInt(pk);
            auto xorPL = convertPk[k] ^ prev[k];
            newKey.push_back(xorPL);
            prev.push_back(xorPL);
            key.push_back(xorPL);
        }
        prev = newKey;
    }
    return key;
}
template <class T>
string convertIntToHex(T t, ios_base & (*f)(ios_base&))
{
    ostringstream oss;
    oss << f << t;
    return oss.str();
}

string convertIntToHexString(vector<int> keyInInt) {
    string keystring;
    for (int i = 0; i < keyInInt.size(); i++) {
        string byte = convertIntToHex<int>(keyInInt[i], hex);
        if (byte.length() == 1) {
            byte = "0" + byte;
        }
        keystring += byte;
    }
    
    return keystring;
}


int main(int argc, const char * argv[]) {
    
    
    vector<string> allkeys;
    
    //cout << hex << (int) sbox[2][11] << '\n';
    
    
    for (int i = 0; i < 10; i++) {
        
        auto keyvector = ConvertKeyInto4Groups(key);
        
        auto last4bytes = DoRotWordOnLast(keyvector[3]);
        
        auto positions = GetSubBytePosition(last4bytes);
        
        //1. SubByte
        auto subyte = SubByte(positions);
        //2. RCON
        auto getRcon = rcon[i]; //TODO: this 0 will be replaced with the number of rounds i.e. i
        //3. Apply this to each group of 4 bytes, starting from the first one
        auto firstFour = keyvector[0];
        //4. XOR subByte, GetRCON, FirstFour
        auto firstFourInts = StringToInt(firstFour);
    
        //xor the last word: subbyte, rcon, firstfour
        auto result = firstXOR(subyte, getRcon, firstFourInts);
        
        //generate a new key
        auto nextKey = generateKey(keyvector, result);
        
        //convert int key to string key
        auto newKeyString = convertIntToHexString(nextKey);
        
        //save key
        allkeys.push_back(newKeyString);
        
        //new key becomes last key
        //TODO: convert nextkey from int to hex and then string.
        //keyvector = nextKey;
        
        key = newKeyString;
    }
    
    
    
    for (int i=0; i< allkeys.size(); i++) {
        cout << i << ": " << allkeys[i] << endl;
    }
    
    
    
    return 0;
}

/*
 
 0: a0fafe1788542cb123a339392a6c7605
 1: f2c295f27a96b9435935807a7359f67f
 2: 3d80477d4716fe3e1e237e446d7a883b
 3: ef44a541a8525b7fb671253bdb0bad00
 4: d4d1c6f87c839d87caf2b8bc11f915bc
 5: 6d88a37a110b3efddbf98641ca0093fd
 6: 4e54f70e5f5fc9f384a64fb24ea6dc4f
 7: ead27321b58dbad2312bf5607f8d292f
 8: ac7766f319fadc2128d12941575c006e
 9: d014f9a8c9ee2589e13f0cc8b6630ca6
 
 
 */

