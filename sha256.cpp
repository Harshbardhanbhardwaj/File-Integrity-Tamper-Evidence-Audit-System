#include "fiaudit/sha256.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <vector>

#if defined(__x86_64__) || defined(__i386__)
#  include <cpuid.h>
#  include <immintrin.h>
#  define FIA_X86 1
#endif

#include "fiaudit/util.hpp"

namespace fia {

namespace {
constexpr std::uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
} // namespace

void Sha256::reset() noexcept {
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85; state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f; state_[5] = 0x9b05688c; state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
    bitlen_ = 0;
    buflen_ = 0;
}

static void sw_transform(std::uint32_t state_[8], const std::uint8_t b[64]) noexcept {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)   // big-endian load (independent of host endianness)
        w[i] = (std::uint32_t(b[4 * i]) << 24) | (std::uint32_t(b[4 * i + 1]) << 16) |
               (std::uint32_t(b[4 * i + 2]) << 8) | std::uint32_t(b[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_[0], bb = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
        std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        std::uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
        std::uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
    }
    state_[0] += a; state_[1] += bb; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}


#ifdef FIA_X86
// ---- x86 SHA extensions ---------------------------------------------------
// Each sha256rnds2 performs two rounds; sha256msg1/msg2 compute the message
// schedule four words at a time.  Compiled for the "sha" target only for this
// function so the rest of the binary still runs on any x86-64 CPU.
__attribute__((target("sha,sse4.1,ssse3")))
static void hw_transform(std::uint32_t state[8], const std::uint8_t* data, std::size_t nblocks) noexcept {
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i TMP = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i STATE1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    TMP = _mm_shuffle_epi32(TMP, 0xB1);                 // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);           // EFGH
    __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);   // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);        // CDGH

    while (nblocks--) {
        const __m128i ABEF_SAVE = STATE0, CDGH_SAVE = STATE1;
        __m128i m[4];
        for (int i = 0; i < 16; ++i) {
            if (i < 4) {
                m[i] = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16 * i)), MASK);
            } else {
                __m128i w1 = m[(i + 3) & 3], w2 = m[(i + 2) & 3];
                __m128i t = _mm_add_epi32(_mm_sha256msg1_epu32(m[i & 3], m[(i + 1) & 3]),
                                          _mm_alignr_epi8(w1, w2, 4));
                m[i & 3] = _mm_sha256msg2_epu32(t, w1);
            }
            __m128i msg = _mm_add_epi32(m[i & 3], _mm_loadu_si128(reinterpret_cast<const __m128i*>(&K[4 * i])));
            STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, msg);
            msg = _mm_shuffle_epi32(msg, 0x0E);
            STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, msg);
        }
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
        data += 64;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);              // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);           // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);        // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);           // HGFE
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), STATE0);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), STATE1);
}

static bool cpu_has_shani() noexcept {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return false;
    bool ssse3 = c & (1u << 9), sse41 = c & (1u << 19);
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return false;
    bool sha = b & (1u << 29);
    return ssse3 && sse41 && sha;
}
#else
static bool cpu_has_shani() noexcept { return false; }
#endif

static std::atomic<bool> g_hw_enabled{cpu_has_shani() && !std::getenv("FIAUDIT_NO_SHANI")};

bool Sha256::hardware_supported() noexcept { return cpu_has_shani(); }
bool Sha256::hardware_enabled() noexcept { return g_hw_enabled.load(std::memory_order_relaxed); }
void Sha256::set_hardware_enabled(bool on) noexcept { g_hw_enabled.store(on && cpu_has_shani()); }

void Sha256::transform_blocks(const std::uint8_t* p, std::size_t nblocks) noexcept {
#ifdef FIA_X86
    if (hardware_enabled()) { hw_transform(state_, p, nblocks); return; }
#endif
    for (std::size_t i = 0; i < nblocks; ++i) sw_transform(state_, p + 64 * i);
}

void Sha256::update(const void* data, std::size_t len) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(data);
    bitlen_ += static_cast<std::uint64_t>(len) * 8;
    while (len > 0) {
        if (buflen_ == 0 && len >= 64) {          // fast path: whole blocks straight from the input
            std::size_t nb = len / 64;
            transform_blocks(p, nb);
            p += nb * 64; len -= nb * 64;
            continue;
        }
        std::size_t take = 64 - buflen_;
        if (take > len) take = len;
        std::memcpy(buf_ + buflen_, p, take);
        buflen_ += take; p += take; len -= take;
        if (buflen_ == 64) { transform_blocks(buf_, 1); buflen_ = 0; }
    }
}

Digest Sha256::final() noexcept {
    std::uint64_t bits = bitlen_;
    buf_[buflen_++] = 0x80;
    if (buflen_ > 56) {
        std::memset(buf_ + buflen_, 0, 64 - buflen_);
        transform_blocks(buf_, 1);
        buflen_ = 0;
    }
    std::memset(buf_ + buflen_, 0, 56 - buflen_);
    for (int i = 0; i < 8; ++i) buf_[56 + i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    transform_blocks(buf_, 1);
    Digest out{};
    for (int i = 0; i < 8; ++i) {
        out[4 * i]     = static_cast<std::uint8_t>(state_[i] >> 24);
        out[4 * i + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
        out[4 * i + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
        out[4 * i + 3] = static_cast<std::uint8_t>(state_[i]);
    }
    return out;
}

Digest Sha256::hash(std::string_view s) noexcept {
    Sha256 h;
    h.update(s);
    return h.final();
}

std::string Sha256::hash_hex(std::string_view s) { return to_hex(hash(s)); }

Digest Sha256::hash_file(const std::string& path) {
    Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (!fd.valid()) throw SysError("open " + path);
    struct stat st;
    if (::fstat(fd.get(), &st) != 0) throw SysError("fstat " + path);
    if (!S_ISREG(st.st_mode)) throw SysError("not a regular file: " + path, EINVAL);
    ::posix_fadvise(fd.get(), 0, 0, POSIX_FADV_SEQUENTIAL);

    static thread_local std::vector<std::uint8_t> buf(64 * 1024);
    Sha256 h;
    for (;;) {
        ssize_t n = ::read(fd.get(), buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            throw SysError("read " + path);
        }
        if (n == 0) break;
        h.update(buf.data(), static_cast<std::size_t>(n));
    }
    return h.final();
}

} // namespace fia
