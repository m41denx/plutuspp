#include <cstdint>
#include <fstream>
#include <stdexcept>

namespace rnd {
    const int NUM_OS_RANDOM_BYTES = 32;
    [[noreturn]] static void RandFailure() {throw std::runtime_error("Failed to read randomness, aborting");}
#ifndef WIN32 //Unix-like (Linux/macOS)
    void GetDevURandom(unsigned char *ent32) {
        std::ifstream f("/dev/urandom", std::ios::binary);
        if (!f.is_open()) RandFailure();
        int have = 0;
        do {
            f.read((char *)ent32 + have, NUM_OS_RANDOM_BYTES - have);
            ssize_t n = f.gcount();
            if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
                f.close();
                RandFailure();
            }
            have += n;
        } while (have < NUM_OS_RANDOM_BYTES);
    }
#endif

    void GetOSRand(unsigned char *ent32) {
#if defined(WIN32) //For Windows
  HCRYPTPROV hProvider;
  int ret = CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  if (!ret) RandFailure();
  ret = CryptGenRandom(hProvider, NUM_OS_RANDOM_BYTES, ent32);
  if (!ret) RandFailure();
  CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_SYS_GETRANDOM) //Linux Built-in getRandom()
  int rv = syscall(SYS_getrandom, ent32, NUM_OS_RANDOM_BYTES, 0);
  if (rv != NUM_OS_RANDOM_BYTES) {
    if (rv < 0 && errno == ENOSYS) GetDevURandom(ent32);
    else RandFailure();
  }
#elif defined(HAVE_GETENTROPY) && defined(__OpenBSD__) //OpenBSD Built-in getEntropy()
  if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) RandFailure();

#elif defined(HAVE_GETENTROPY_RAND) && defined(MAC_OSX) //macOS (Fallback for <10.12)
  if (&getentropy != nullptr) {
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) RandFailure();
  } else GetDevURandom(ent32);
#elif defined(HAVE_SYSCTL_ARND) //FreeBSD
  static const int name[2] = {CTL_KERN, KERN_ARND};
  int have = 0;
  do {
    size_t len = NUM_OS_RANDOM_BYTES - have;
    if (sysctl(name, ARRAYLEN(name), ent32 + have, &len, nullptr, 0) != 0) RandFailure();
    have += len;
  } while (have < NUM_OS_RANDOM_BYTES);
#else //Like that should work i guess
        GetDevURandom(ent32);
#endif
    }
    class Rand_OS {
    public:
        const uint8_t *get_buff() const { return buff_; }
        int get_buff_size() const { return NUM_OS_RANDOM_BYTES; }
        void Rand(){ GetOSRand(buff_); }
    private:
        uint8_t buff_[NUM_OS_RANDOM_BYTES];
    };

}

