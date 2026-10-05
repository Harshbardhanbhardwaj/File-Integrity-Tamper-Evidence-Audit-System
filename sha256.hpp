// sha256.hpp - self-contained SHA-256 (FIPS 180-4).
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "fiaudit/types.hpp"

namespace fia {

class Sha256 {
public:
    Sha256() noexcept { reset(); }
    void reset() noexcept;
    void update(const void* data, std::size_t len) noexcept;
    void update(std::string_view s) noexcept { update(s.data(), s.size()); }
    Digest final() noexcept;   // object must be reset() before reuse

    static Digest      hash(std::string_view s) noexcept;
    static std::string hash_hex(std::string_view s);
    // Streams the file in 64 KiB chunks. Throws SysError. Regular files only.
    static Digest      hash_file(const std::string& path);

    // Computer-architecture feature: x86 SHA-NI instructions (runtime CPUID dispatch).
    static bool hardware_supported() noexcept;     // CPU has SHA-NI (+SSSE3/SSE4.1)
    static bool hardware_enabled() noexcept;       // currently used
    static void set_hardware_enabled(bool on) noexcept;   // tests / FIAUDIT_NO_SHANI=1

private:
    void transform_blocks(const std::uint8_t* p, std::size_t nblocks) noexcept;
    std::uint32_t state_[8];
    std::uint64_t bitlen_;
    std::uint8_t  buf_[64];
    std::size_t   buflen_;
};

} // namespace fia
