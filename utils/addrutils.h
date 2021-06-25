#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <typeinfo>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <algorithm>
#include <math.h>
#include <assert.h>
#include <cstdint>

namespace utils {
int sha256(const uint8_t preimageBytes[], size_t len, std::vector<uint8_t>& res){
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, preimageBytes, len); 
	int ret = SHA256_Final(&res[0], &sha256);
	return ret;
}


int ripemd160(const uint8_t preimageBytes[], size_t len, std::vector<uint8_t>& res){
	RIPEMD160_CTX ripemd160;
	RIPEMD160_Init(&ripemd160);
	RIPEMD160_Update(&ripemd160, preimageBytes, len);
	int ret = RIPEMD160_Final(&res[0], &ripemd160);
	return ret;
}

void switchEndianness(std::vector<uint8_t>& b){
	std::reverse(b.begin(), b.end());
}

int hexDigitToInt(char digit){
	digit = tolower(digit);
	if (digit >= '0' && digit <='9')
	       return (int)(digit - '0');
	else if (digit >= 'a' && digit <= 'f') {
		return (int)(digit - '1' - '0') + 10; 
	}	
	return -1;
}

int hexstringToIntArray(std::string const& hexstring, uint8_t result[]){
	if (hexstring.size() % 2) {
		std::cerr << "The hexstring is not an even number of characters.\n";
		exit(EXIT_FAILURE);
	}
	
	size_t resultLength = hexstring.size() / 2;
	size_t i = 0;
	for (auto it = hexstring.begin(); it != hexstring.end(); it = it + 2) {
		int sixteens = hexDigitToInt(*it);
		int units = hexDigitToInt(*std::next(it));
		result[i] = (sixteens << 4) | units;
		i++;
	}
	return resultLength;
}

int hexstringToBytes(std::string const& hexstring, std::vector<uint8_t>& result)
{
	if (hexstring.size() % 2) {
		std::cerr << "The hexstring is not an even number of characters.\n";
		exit(EXIT_FAILURE);
	}
	
	size_t resultLength = hexstring.size() / 2;
	size_t i = 0;
	for (auto it = hexstring.begin(); it != hexstring.end(); it = it + 2) {
		int sixteens = hexDigitToInt(*it);
		int units = hexDigitToInt(*std::next(it));
		result.push_back((sixteens << 4) | units);
		i++;
	}
	return resultLength;
}
	
	
/**
 * Print a string as hexadecimal values.
 *
 * */ 
void printToHex(std::string s)
{
	std::cout << "printToHex() for " << s << ": ";
	for(size_t i = 0; i < s.size(); i++) {
		std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)s[i];
	}
	std::cout << '\n';
}

/**
 * Print a string as hexadecimal values using printf()
 *
 * */ 
void printToHexCStyle(std::string s)
{
	std::cout << "printToHex() for " << s << ": ";
	for(size_t i = 0; i < s.size(); i++) {
		printf("%02hhx", s[i]);
	}
	std::cout << '\n';
}

/**
 *
 * return a hex string representation of the value of an integer
 *
 * */ 
std::string intToHexString1(int num)
{
	std::stringstream ss;
	ss << std::hex << num;
	return ss.str();
}

/**
 * Convert an int to a hexadecimal string, using arithmetic.
 *
 * */
std::string intToHexString2(int num)
{
	const char hexChars[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	std::string result;
	while (num) {
		char tmp = hexChars[num % 16];
		result.insert(result.begin(), tmp);
		num /= 16;
	}
	return result;
}

/**
 * Build a hex string representation of bytes.
 * 
 * */
void charToHexString(const char& c, std::string& s)
{
	std::stringstream ss;
	ss << std::setfill('0') << std::setw(2) << std::hex << (0xff & (int)c);
	s.append(ss.str());
}
}



std::string EncodeBase58(const uint8_t* pbegin, const uint8_t* pend)
{
    static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
	int zeroes = 0;
	int length = 0;
	while (pbegin != pend && *pbegin == 0) {
		pbegin++;
		zeroes++;
	}
	int size = (pend - pbegin) * 138 / 100 + 1;
	std::vector<uint8_t> b58(size);
	while (pbegin != pend) {
		int carry = *pbegin;
		int i = 0;
		std::vector<uint8_t>::reverse_iterator it;
		for (it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}

		assert(carry == 0);
		length = i;
		pbegin++;
	}
	std::vector<uint8_t>::iterator it = b58.begin() + (size - length);
	while (it != b58.end() && *it == 0)
		it++;
	std::string str;
	str.reserve(zeroes + (b58.end() - it));
	str.assign(zeroes, '1');
	while (it != b58.end())
		str += pszBase58[*(it++)];
	return str;
}

std::string EncodeBase58(const std::vector<uint8_t>& vch)
{
	return EncodeBase58(vch.data(), vch.data() + vch.size());
}
