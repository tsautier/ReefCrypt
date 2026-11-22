#include "aead.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>
#include <thread>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

namespace fish_aead::test
{
void SetSender(const std::array<unsigned char, 16>& session, std::uint64_t counter);
}

namespace
{
using namespace fish_aead;

void Require(bool condition, const char* description)
{
	if (!condition)
	{
		std::cerr << description << '\n';
		std::exit(1);
	}
}

template <std::size_t N>
std::array<unsigned char, N> DecodeHex(const char* hex)
{
	std::array<unsigned char, N> bytes{};
	std::size_t length = 0;
	Require(OPENSSL_hexstr2buf_ex(bytes.data(), bytes.size(), &length, hex, '\0') == 1 && length == N,
		"Invalid hexadecimal test fixture");
	return bytes;
}

void CheckRfc8439()
{
	// RFC 8439 section 2.8.2, https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
	const auto key = DecodeHex<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
	const auto nonce = DecodeHex<12>("070000004041424344454647");
	const auto aad = DecodeHex<12>("50515253c0c1c2c3c4c5c6c7");
	const auto plaintext = DecodeHex<114>(
		"4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
		"73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
		"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
		"637265656e20776f756c642062652069742e");
	const auto expectedCiphertext = DecodeHex<114>(
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
		"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
		"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
		"3ff4def08e4b7a9de576d26586cec64b6116");
	const auto expectedTag = DecodeHex<16>("1ae10b594f09e26a7e902ecbd0600691");
	const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	std::array<unsigned char, plaintext.size() + EVP_MAX_BLOCK_LENGTH> ciphertext{};
	std::array<unsigned char, expectedTag.size()> tag{};
	int unused = 0;
	int written = 0;
	int final = 0;
	Require(context && EVP_EncryptInit_ex2(context.get(), EVP_chacha20_poly1305(), key.data(), nonce.data(), nullptr) == 1
		&& EVP_EncryptUpdate(context.get(), nullptr, &unused, aad.data(), static_cast<int>(aad.size())) == 1
		&& EVP_EncryptUpdate(context.get(), ciphertext.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) == 1
		&& written == static_cast<int>(plaintext.size()) && EVP_EncryptFinal_ex(context.get(), ciphertext.data() + written, &final) == 1
		&& final == 0 && EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1,
		"RFC 8439 OpenSSL encryption failed");
	Require(std::equal(expectedCiphertext.begin(), expectedCiphertext.end(), ciphertext.begin()) && expectedTag == tag,
		"OpenSSL ciphertext or tag differs from RFC 8439");
}

void CheckGolden(const Key& key)
{
	const std::string documented = "+FISH-AEAD1 AAECAwQFBgcICQoLDA0ODwAAAAAAAAAqIh-TRZVRgruC7Hwd9SKxUA8g_XMNDZC1MbRmtQ";
	std::string plaintext;
	Require(Open(key, documented, plaintext) && plaintext == "FiSH AEAD v1", "Documented reference vector failed");

	// Independent Node.js crypto vector. Session f0 through ff, counter 42,
	// conversation key 00 through 1f, and ciphertext authenticated with the wire header.
	const std::string golden = "+FISH-AEAD1 8PHy8_T19vf4-fr7_P3-_wAAAAAAAAAqX-cRy6PJPE9HuUPEkwVfzdqpRqBkOWoqRioqNa3TCHvXDGI5aRLDuuTs";
	std::string tampered = golden;
	tampered[Marker.size() + 32] = 'A';
	plaintext = "unchanged";
	Require(!Open(key, tampered, plaintext) && plaintext == "unchanged", "Tampered frame altered plaintext or passed authentication");
	Require(ERR_peek_error() == 0, "Authentication polluted an empty OpenSSL error queue");
	ERR_raise(ERR_LIB_USER, 17);
	const auto priorError = ERR_peek_error();
	Require(!Open(key, tampered, plaintext) && ERR_get_error() == priorError && ERR_peek_error() == 0,
		"Authentication disturbed a preexisting OpenSSL error");
	Require(Open(key, golden, plaintext) && plaintext == "FiSH AEAD interoperability", "Independent wire vector failed");
	Require(!Open(key, golden, plaintext), "Golden frame replay accepted");

	// The authenticated invalid plaintext uses a far-future counter. The valid
	// counter 43 must remain acceptable when the invalid message is rejected.
	const std::string invalidText = "+FISH-AEAD1 8PHy8_T19vf4-fr7_P3-_wAAAAAAAAPpBvXMlD2QVySdME72_RCbOK6HrWYkHhMtI0as8yWwzg";
	const std::string next = "+FISH-AEAD1 8PHy8_T19vf4-fr7_P3-_wAAAAAAAAArJf3SfG5mKroROgxGIyd9bSLvEdXnCaCtk6o";
	Require(!Open(key, invalidText, plaintext), "Authenticated NUL in plaintext accepted");
	Require(Open(key, next, plaintext) && plaintext == "after auth", "Invalid frame advanced replay window");

	const std::string canonical = "+FISH-AEAD1 8PHy8_T19vf4-fr7_P3-_wAAAAAAAAAsBaagEgMSH5-y354hk1D8Up-w";
	std::string nonCanonical = canonical;
	nonCanonical.back() = 'x'; // Same decoded bytes with nonzero unused bits.
	Require(!Open(key, nonCanonical, plaintext), "Noncanonical base64url accepted");
	Require(!Open(key, canonical + "=", plaintext), "Padded base64url accepted");
	Require(Open(key, canonical, plaintext) && plaintext == "OK", "Canonical frame rejected after malformed equivalents");
}

void CheckLimits(const Key& key)
{
	std::string frame = "unchanged";
	Require(!Seal(key, "", frame) && frame == "unchanged", "Empty plaintext was accepted");
	Require(!Seal(key, "line\rbreak", frame), "Carriage return was accepted");
	Require(!Seal(key, "line\nbreak", frame), "Line feed was accepted");
	Require(!Seal(key, std::string_view("a\0b", 3), frame), "NUL was accepted");
	Require(!Seal(key, std::string(MaxPlaintextLength + 1, 'x'), frame), "Oversized plaintext was accepted");
	std::string plaintext(MaxPlaintextLength, 'x');
	Require(Seal(key, plaintext, frame) && frame.size() == MaxFrameLength, "Maximum-length frame was rejected");
	std::string opened;
	Require(!Open(key, frame + 'A', opened), "Oversized frame was accepted");
	Require(Open(key, frame, opened) && opened == plaintext, "Maximum-length round trip failed");
}

void CheckReplayWindow(const Key& key)
{
	std::array<std::string, 66> frames;
	for (auto& frame : frames)
		Require(Seal(key, "counter window", frame), "Could not produce frame for counter window");
	std::string opened;
	Require(Open(key, frames.back(), opened), "Highest counter rejected");
	Require(!Open(key, frames[1], opened), "Counter 64 behind the highest was accepted");
	Require(Open(key, frames[2], opened), "Unseen counter 63 behind the highest was rejected");
	Require(!Open(key, frames[2], opened), "Previously seen reordered counter accepted");
	Key wrongKey = key;
	wrongKey.back() ^= 0x80;
	Require(!Open(wrongKey, frames[3], opened), "Frame authenticated with the wrong key");
	Require(Open(key, frames[3], opened), "Failed authentication consumed counter");
}

void CheckConcurrent(const Key& key)
{
	constexpr int ThreadCount = 8;
	constexpr int FramesPerThread = 16;
	std::array<std::string, ThreadCount * FramesPerThread> frames;
	std::vector<std::jthread> threads;
	for (int id = 0; id < ThreadCount; ++id)
	{
		threads.emplace_back([&, id] {
			for (int i = 0; i < FramesPerThread; ++i)
				Require(Seal(key, "concurrent frame", frames[id * FramesPerThread + i]), "Concurrent seal failed");
		});
	}
	threads.clear(); // Joining all workers makes every frame visible to this thread.
	std::set<std::string_view> headers;
	for (const auto& frame : frames)
	{
		// The first 32 base64url characters encode the 24-byte header exactly.
		headers.insert(std::string_view(frame).substr(Marker.size(), 32));
	}
	Require(headers.size() == frames.size(), "Concurrent seals reused a session and counter");

	std::string frame;
	Require(Seal(key, "concurrent replay", frame), "Could not produce replay fixture");
	std::atomic<int> accepted = 0;
	for (int id = 0; id < ThreadCount; ++id)
	{
		threads.emplace_back([&] {
			std::string opened;
			if (Open(key, frame, opened))
				++accepted;
		});
	}
	threads.clear();
	Require(accepted == 1, "Concurrent replay was accepted more or less than once");
}

std::array<unsigned char, 24> DecodeHeader(std::string_view frame)
{
	std::string encoded(frame.substr(Marker.size(), 32));
	std::replace(encoded.begin(), encoded.end(), '-', '+');
	std::replace(encoded.begin(), encoded.end(), '_', '/');
	std::array<unsigned char, 24> header{};
	Require(EVP_DecodeBlock(header.data(), reinterpret_cast<const unsigned char*>(encoded.data()), 32) == 24,
		"Could not decode the test frame header");
	return header;
}

void CheckStateBoundaries(const Key& key)
{
	std::array<unsigned char, 16> session{};
	session.fill(0xff);
	test::SetSender(session, UINT64_MAX - 1);
	std::string frame;
	Require(Seal(key, "penultimate", frame), "The penultimate counter was rejected");
	auto header = DecodeHeader(frame);
	Require(std::all_of(header.begin(), header.end() - 1, [](auto byte) { return byte == 0xff; }) && header.back() == 0xfe,
		"The penultimate counter was encoded incorrectly");
	Require(Seal(key, "last", frame), "The final counter was rejected");
	header = DecodeHeader(frame);
	Require(std::all_of(header.begin(), header.end(), [](auto byte) { return byte == 0xff; }), "The final counter was encoded incorrectly");
	const std::string last = frame;
	Require(!Seal(key, "must not wrap", frame) && frame == last, "Exhausted send counter reused a nonce or changed output");

	Key wrongKey = key;
	wrongKey[0] ^= 0x80;
	session.fill(0);
	std::string plaintext;
	std::string first;
	for (std::uint32_t i = 0; i < 4096; ++i)
	{
		session[0] = static_cast<unsigned char>(i >> 8);
		session[1] = static_cast<unsigned char>(i);
		test::SetSender(session, 0);
		Require(Seal(key, "new epoch", frame), "Could not seal a capacity fixture");
		Require(!Open(wrongKey, frame, plaintext), "Wrong key accepted while filling replay state");
		Require(Open(key, frame, plaintext), "Replay capacity was consumed by unauthenticated input or filled prematurely");
		if (i == 0)
			first = frame;
	}
	session[0] = 0x10;
	session[1] = 0;
	test::SetSender(session, 0);
	Require(Seal(key, "epoch beyond capacity", frame) && !Open(key, frame, plaintext), "Replay state accepted a 4097th epoch");
	session[0] = 0;
	test::SetSender(session, 1);
	Require(!Open(key, first, plaintext), "An epoch at capacity was evicted or lost replay history");
	Require(Seal(key, "existing epoch", frame) && Open(key, frame, plaintext), "A full replay state blocked an existing epoch");
	std::cout << "FiSH AEAD counter exhaustion and authenticated epoch capacity tests passed\n";
}

void CheckUnavailableProvider(const Key& key)
{
	// In a new process the null provider disables the default RNG and crypto.
	const std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)>
		provider(OSSL_PROVIDER_load(nullptr, "null"), OSSL_PROVIDER_unload);
	Require(provider != nullptr, "Could not initialize the null provider in the isolated test process");
	std::string frame = "unchanged";
	Require(!Seal(key, "fail closed", frame) && frame == "unchanged", "Seal returned output when the RNG was unavailable");
	Require(ERR_peek_error() == 0, "RNG failure polluted an empty OpenSSL error queue");
	ERR_raise(ERR_LIB_USER, 19);
	const auto priorError = ERR_peek_error();
	Require(!Seal(key, "fail closed", frame) && ERR_get_error() == priorError && ERR_peek_error() == 0,
		"RNG failure disturbed a preexisting OpenSSL error");
	std::cout << "FiSH AEAD unavailable-provider test passed\n";
}
}

int main(int argc, char** argv)
{
	static_assert(sizeof(void*) == 4, "Build the AEAD test for Win32");
	Key key{};
	Require(ParseKey("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key), "Valid 256-bit key rejected");
	const Key original = key;
	Require(!ParseKey("ABC123", key) && key == original, "Reject a short key without changing output");
	Require(!ParseKey(std::string(64, 'z'), key) && key == original, "Reject nonhexadecimal key without changing output");
	if (argc == 2 && std::string_view(argv[1]) == "--state-boundaries")
	{
		CheckStateBoundaries(key);
		return 0;
	}
	if (argc == 2 && std::string_view(argv[1]) == "--unavailable-provider")
	{
		CheckUnavailableProvider(key);
		return 0;
	}
	if (argc == 2 && std::string_view(argv[1]) == "--first-frame")
	{
		std::string frame;
		Require(Seal(key, "restart check", frame), "Could not seal restart fixture");
		std::cout << frame << '\n';
		return 0;
	}
	CheckRfc8439();
	CheckGolden(key);
	CheckLimits(key);
	CheckReplayWindow(key);
	CheckConcurrent(key);
	std::cout << "FiSH AEAD codec, authentication, replay and concurrency tests passed\n";
}
