#include <iostream>
#include <sodium.h>
#include <string>
#include "utils/hashing.h"
#include "utils/key.h"


void genprivkey(char *xrand);
void genpublickey(char *privKey);
void base58(char* hexAddr);
std::string toHex(const std::string& input);
std::vector<std::vector<std::string>> genKey(unsigned short int rounds);

/* Chain Ring:
 *      privateKey
 *      publicKey
 *      WIF
 *      addressUncompressed
 *      addressCompressed
 */


int main() {
    unsigned short int n=1;
    //std::cout<<"To generate: ";
    //std::cin>>n;
    std::vector<std::vector<std::string>> res;
    res=genKey(n);
}

std::vector<std::vector<std::string>> genKey(unsigned short int rounds){
    std::vector<std::vector<std::string>> chain;
    for(unsigned short int r=0;r<rounds;r++){
        std::vector<std::string> ring;
        //gen privKey
        ecdsa::Key pKey;

        std::vector<uint8_t> pkk=pKey.get_priv_key_data();
        std::string privateKey(pkk.begin(), pkk.end());
        ring.push_back(toHex(privateKey));

        //gen pubKey
        std::vector<uint8_t> pkp=pKey.get_pub_key_data();
        bool dummy = pKey.CalculatePublicKey(true);
        std::vector<uint8_t> pkp_compressed=pKey.get_pub_key_data();
        std::string publicKey(pkp.begin(), pkp.end());
        ring.push_back(toHex(publicKey));

        //std::cout<<"["<<toHex(privateKey)<<" | "<<toHex(publicKey)<<"]";
    }

    return chain;
}

std::string toHex(const std::string& input){
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input){
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}