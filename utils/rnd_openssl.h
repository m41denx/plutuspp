#include <openssl/rand.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

namespace rnd {
    int64_t GetPerformanceCounter() {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
        return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
        uint64_t r = 0;
  __asm__ volatile("rdtsc"
                   : "=A"(r));  // Constrain the r variable to the eax:edx pair.
  return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
        uint64_t r1 = 0, r2 = 0;
  __asm__ volatile("rdtsc"
                   : "=a"(r1), "=d"(r2));  // Constrain r1 to rax and r2 to rdx.
  return (r2 << 32) | r1;
#else
        // Fall back to using C++11 clock (usually microsecond or nanosecond
        // precision)
        return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
    }

template <int BUFF_SIZE>
class Rand_OpenSSL {
 public:
  Rand_OpenSSL() {
    memset(buff_, 0, BUFF_SIZE);
    int64_t counter = GetPerformanceCounter();
    RAND_add(&counter, sizeof(counter), 1.5);
    std::memset(&counter, 0, sizeof(counter));
  }

  const uint8_t *get_buff() const { return buff_; }
  int get_buff_size() const { return BUFF_SIZE; }

  void Rand() { assert(RAND_bytes(buff_, BUFF_SIZE) == 1); }

 private:
  uint8_t buff_[BUFF_SIZE];
};
}