#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

namespace fish_aead
{
using Key = std::array<unsigned char, 32>;

inline constexpr std::string_view Marker = "+FISH-AEAD1 ";
inline constexpr std::size_t MaxFrameLength = 512;
// The decoded frame has a 16-byte session, an 8-byte counter and a 16-byte tag.
inline constexpr std::size_t MaxPlaintextLength = (MaxFrameLength - Marker.size()) * 3 / 4 - 40;

// Parse exactly 32 hexadecimal bytes. Output arguments are assigned on success only.
bool ParseKey(std::string_view hex, Key& key);
bool Seal(const Key& key, std::string_view plaintext, std::string& frame);

// Open authenticates the entire frame and rejects replays for this process lifetime.
bool Open(const Key& key, std::string_view frame, std::string& plaintext);
}
