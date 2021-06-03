#include <cstdint>
#include <vector>
#include <cstring>
#include <openssl/sha.h>

namespace rnd {

class RandManager {
 public:
  explicit RandManager(int buff_size = 32) : buff_size_(buff_size) {}
  void Begin() { SHA512_Init(&sha_ctx_); }
  std::vector<uint8_t> End(){
      SHA512_Final(md_, &sha_ctx_);
      std::vector<uint8_t> result;
      result.resize(buff_size_);
      std::memcpy(result.data(), md_, buff_size_);
      return result;
  }
  template <typename RandOpt>
  void Rand() {
    RandOpt rand;
    rand.Rand();
    const uint8_t *rnd_result = rand.get_buff();
    int rnd_result_size = rand.get_buff_size();
    HashBuff(rnd_result, rnd_result_size);
  }

 private:
  void HashBuff(const uint8_t *buff, int size) {
        SHA512_Update(&sha_ctx_, buff, size);
    }

 private:
  int buff_size_;
  SHA512_CTX sha_ctx_;
  uint8_t md_[SHA512_DIGEST_LENGTH];
};
}

