#include <vector>
#include <string>


std::string EncodeBase58(std::string dat)
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

