#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>



std::string sha256(const std::string dat)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, dat.c_str(), dat.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}




std::string b58encode(std::string dat)
{
    const unsigned char mapping[] = { //BASE58 Core stuff
            '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J',
            'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
            'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z' };

    const std::vector<unsigned char> data(dat.begin(), dat.end());

    std::vector<unsigned char> digits((data.size() * 138 / 100) + 1);
    unsigned long digitslen = 1;
    for (unsigned long i = 0; i < data.size(); i++)
    {
        unsigned int carry = static_cast<unsigned int>(data[i]);
        for (unsigned long j = 0; j < digitslen; j++)
        {
            carry = carry + static_cast<unsigned int>(digits[j] << 8);
            digits[j] = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }
        for (; carry; carry /= 58)
            digits[digitslen++] = static_cast<unsigned char>(carry % 58);
    }
    std::string result;
    for (unsigned long i = 0; i < (data.size() - 1) && !data[i]; i++)
        result.push_back(mapping[0]);
    for (unsigned long i = 0; i < digitslen; i++)
        result.push_back(mapping[digits[digitslen - 1 - i]]);
    return result;
}



std::string ripemd160(std::string dat){
    unsigned char data[32];
    strcpy((char*) data, dat.c_str());
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, data, dat.size());
    RIPEMD160_Final(hash, &ripemd160);
    std::ostringstream oss;
    for(int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << +hash[i];
    }
    auto hashString = oss.str();

    return hashString;
}


