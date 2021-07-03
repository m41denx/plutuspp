#include <iostream>
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <string>
#include "utils/key.h"
#include "utils/addrutils.h"
#include <thread>


std::string toHex(const std::string& input);
void genKey(unsigned long int rounds, std::vector<std::vector<std::string>> &res);
void genThread(char id, unsigned long int work, std::vector<std::string> &AddrList);

/* Chain Ring:
 *      privateKey
 *      publicKey
 *      addressUncompressed
 *      addressCompressed
 */


int main(int argc, char* argv[]) {
    unsigned long int n=atoi(argv[2])*4;
    unsigned char cores=std::thread::hardware_concurrency();

    //STATS
    std::cout<<"THREADS: "<<int(cores)<<"\nWork: "<<n<<"\nPopulating from "<<argv[1]<<std::endl;

    //READ BUF
    std::ifstream addrListFile(argv[1]);
    std::vector<std::string> AddrList;
    std::string bufAddr;
    while(std::getline(addrListFile, bufAddr)){
        AddrList.push_back(bufAddr);
    }
    std::cout<<"Got "<<AddrList.size()<<" Addresses"<<std::endl;

    std::vector<std::thread> thrList;
    for(unsigned char thr=0; thr<cores;thr++){
        std::thread calcThread(genThread, thr, n/cores, std::ref(AddrList));
        thrList.push_back(std::move(calcThread));
    }
    for(unsigned char thr=0; thr<cores;thr++){
        thrList.at(thr).join();
    }
}


void genThread(char id, unsigned long int work, std::vector<std::string> &AddrList){
    std::vector<std::vector<std::string>> res;
    genKey(work, std::ref(res));
    std::cout<<"[THR #"<<int(id)<<"] ADDRESSES SCATTERED: "<<work<<"\nSearching"<<std::endl;
    int psc=0;
    for(std::vector<std::string> elem: res){
        if(
            std::find(AddrList.begin(), AddrList.end(), elem.at(2)) != AddrList.end()
            || std::find(AddrList.begin(), AddrList.end(), elem.at(2)) != AddrList.end()
        ){
            std::cout<<"Holy memes!!! Addr found:\n-----------------\n"
            <<"PRIVATE KEY: "<<elem.at(0)<<"\nPUBLIC KEY: "<<elem.at(1)<<"\nADDRESS:\n\tSTD: "<<elem.at(2)<<"\n\tCOMP: "<<elem.at(3)<<std::endl;
        }
//        psc++;
//        if(psc==256){std::cout<<".";psc=0;}
    }
}


void genKey(unsigned long int rounds, std::vector<std::vector<std::string>> &res){
    for(unsigned short int r=0;r<rounds;r++){
        std::vector<std::string> ring;
        //gen privKey
        ecdsa::Key pKey;

        std::vector<uint8_t> pkk=pKey.get_priv_key_data();
        std::string privateKey(pkk.begin(), pkk.end());
        ring.push_back(toHex(privateKey));

        //gen pubKey
        std::vector<uint8_t> pkp=pKey.get_pub_key_data();
        std::string publicKey(pkp.begin(), pkp.end());
        ring.push_back(toHex(publicKey));

        //gen compressed
        bool dummy = pKey.CalculatePublicKey(true);
        std::vector<uint8_t> pkp_compressed=pKey.get_pub_key_data();
        std::string publicKeyCompressed(pkp_compressed.begin(), pkp_compressed.end());
        
        //gen uncomp address
	    std::vector<uint8_t> publicKeyVector;
	    utils::hexstringToBytes(toHex(publicKey), publicKeyVector);
        std::vector<uint8_t> addressSHA256(SHA256_DIGEST_LENGTH);
	    utils::sha256(publicKeyVector.data(), publicKeyVector.size(), addressSHA256);
        std::vector<uint8_t> addressRipemd(RIPEMD160_DIGEST_LENGTH);
	    utils::ripemd160(&addressSHA256[0], addressSHA256.size(), addressRipemd);
	    addressRipemd.insert(std::begin(addressRipemd), 0x00);
	    std::vector<uint8_t> addressHash(SHA256_DIGEST_LENGTH);
	    utils::sha256(&addressRipemd[0], addressRipemd.size(), addressHash);
	    utils::sha256(&addressHash[0], addressHash.size(), addressHash);
	    std::vector<uint8_t>::const_iterator address_iter_first = addressHash.begin();
	    std::vector<uint8_t>::const_iterator address_iter_last = address_iter_first + 4;
	    addressRipemd.insert(addressRipemd.end(), address_iter_first, address_iter_last);
        std::string address = EncodeBase58(addressRipemd);
        ring.push_back(address);

        //gen comp address
        std::vector<uint8_t> publicKeyCompressedVector;
	    utils::hexstringToBytes(toHex(publicKeyCompressed), publicKeyCompressedVector);
        std::vector<uint8_t> addressCompressedSHA256(SHA256_DIGEST_LENGTH);
	    utils::sha256(publicKeyCompressedVector.data(), publicKeyCompressedVector.size(), addressCompressedSHA256);
        std::vector<uint8_t> addressCompressedRipemd(RIPEMD160_DIGEST_LENGTH);
	    utils::ripemd160(&addressCompressedSHA256[0], addressCompressedSHA256.size(), addressCompressedRipemd);
	    addressCompressedRipemd.insert(std::begin(addressCompressedRipemd), 0x00);
	    std::vector<uint8_t> addressCompressedHash(SHA256_DIGEST_LENGTH);
	    utils::sha256(&addressCompressedRipemd[0], addressCompressedRipemd.size(), addressCompressedHash);
	    utils::sha256(&addressCompressedHash[0], addressCompressedHash.size(), addressCompressedHash);
	    std::vector<uint8_t>::const_iterator addressCompressed_iter_first = addressCompressedHash.begin();
	    std::vector<uint8_t>::const_iterator addressCompressed_iter_last = addressCompressed_iter_first + 4;
	    addressCompressedRipemd.insert(addressCompressedRipemd.end(), addressCompressed_iter_first, addressCompressed_iter_last);
        std::string addressCompressed = EncodeBase58(addressCompressedRipemd);
        ring.push_back(addressCompressed);


        res.push_back(ring);

//        std::cout<<"PRIVATE KEY: "<<toHex(privateKey)<<"\nPUBLIC KEY:\n\tSTD: "<<toHex(publicKey)<<"\n\tCOMP:"<<toHex(publicKeyCompressed)
//        <<"\nADDRESS:\n\tSTD: "<<address<<"\n\tCOMP: "<<addressCompressed<<std::endl;
    }
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