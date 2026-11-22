#include "aead.h"

#include <algorithm>
#include <compare>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <span>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace fish_aead
{
namespace
{
constexpr std::size_t SessionSize = 16;
constexpr std::size_t CounterSize = 8;
constexpr std::size_t HeaderSize = SessionSize + CounterSize;
constexpr std::size_t TagSize = 16;
constexpr std::size_t MaxWireSize = HeaderSize + MaxPlaintextLength + TagSize;
constexpr std::size_t MaxReplayEpochs = 4096;
constexpr std::size_t ReplayWindowSize = 64;
constexpr std::string_view Base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

using Session = std::array<unsigned char, SessionSize>;
using Header = std::span<const unsigned char, HeaderSize>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfContext = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

struct ErrorQueueScope
{
	const bool marked = ERR_set_mark() == 1;

	~ErrorQueueScope()
	{
		// mIRC uses the same libcrypto and may have its own thread-local errors.
		if (marked)
			ERR_pop_to_mark();
		else
			ERR_clear_error();
	}
};

template <std::size_t N>
struct SensitiveBytes
{
	std::array<unsigned char, N> bytes{};
	~SensitiveBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

struct SendState
{
	std::mutex mutex;
	Session session{};
	std::uint64_t nextCounter = 0;
	bool initialized = false;
	bool exhausted = false;
};

struct Epoch
{
	Session session{};
	std::array<unsigned char, 32> keyDigest{};
	auto operator<=>(const Epoch&) const = default;
};

struct ReplayWindow
{
	std::uint64_t highest;
	std::uint64_t seen;
};

SendState& Sender()
{
	static SendState state;
	return state;
}

bool ReserveHeader(std::span<unsigned char, HeaderSize> header)
{
	auto& state = Sender();
	const std::lock_guard lock(state.mutex);
	if (state.exhausted)
		return false;
	if (!state.initialized)
	{
		if (RAND_bytes(state.session.data(), static_cast<int>(state.session.size())) != 1)
			return false;
		state.initialized = true;
	}

	std::copy(state.session.begin(), state.session.end(), header.begin());
	for (std::size_t i = 0; i < CounterSize; ++i)
		header[HeaderSize - 1 - i] = static_cast<unsigned char>(state.nextCounter >> (8 * i));
	// Reserve before encryption and burn the value on any subsequent failure.
	if (state.nextCounter == UINT64_MAX)
		state.exhausted = true;
	else
		++state.nextCounter;
	return true;
}

bool AcceptCounter(const Key& trafficKey, Header header)
{
	Epoch epoch;
	std::copy_n(header.begin(), SessionSize, epoch.session.begin());
	std::size_t digestLength = 0;
	// Index the replay state without retaining the conversation or traffic key.
	if (EVP_Q_digest(nullptr, "SHA256", nullptr, trafficKey.data(), trafficKey.size(),
		epoch.keyDigest.data(), &digestLength) != 1 || digestLength != epoch.keyDigest.size())
		return false;

	std::uint64_t counter = 0;
	for (const auto byte : header.last<CounterSize>())
		counter = (counter << 8) | byte;

	// Only authenticated, valid messages reach this lock or consume an epoch slot.
	static std::mutex mutex;
	static std::map<Epoch, ReplayWindow> epochs;
	const std::lock_guard lock(mutex);
	const auto found = epochs.find(epoch);
	if (found == epochs.end())
	{
		if (epochs.size() >= MaxReplayEpochs)
			return false;
		epochs.emplace(epoch, ReplayWindow{counter, 1});
		return true;
	}

	auto& window = found->second;
	if (counter > window.highest)
	{
		const auto delta = counter - window.highest;
		window.seen = delta < ReplayWindowSize ? (window.seen << delta) | 1 : 1;
		window.highest = counter;
		return true;
	}

	const auto delta = window.highest - counter;
	if (delta >= ReplayWindowSize)
		return false;
	const auto mask = std::uint64_t{1} << delta;
	if ((window.seen & mask) != 0)
		return false;
	window.seen |= mask;
	return true;
}

bool DeriveTrafficKey(const Key& key, Header header, Key& trafficKey)
{
	const Kdf kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
	if (!kdf)
		return false;
	const KdfContext context(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
	if (!context)
		return false;

	char digest[] = "SHA256";
	char info[] = "FiSH-AEAD1 traffic";
	int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
	const OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
		OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(key.data()), key.size()),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(header.data()), SessionSize),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1),
		OSSL_PARAM_construct_end()
	};
	return EVP_KDF_derive(context.get(), trafficKey.data(), trafficKey.size(), params) == 1;
}

bool InitCipher(EVP_CIPHER_CTX* context, const Key& trafficKey, Header header, bool encrypt)
{
	std::array<unsigned char, 4 + CounterSize> nonce{};
	const auto counter = header.last<CounterSize>();
	std::copy(counter.begin(), counter.end(), nonce.begin() + 4);
	int unused = 0;
	return EVP_CipherInit_ex2(context, EVP_chacha20_poly1305(), trafficKey.data(), nonce.data(), encrypt, nullptr) == 1
		&& EVP_CipherUpdate(context, nullptr, &unused, reinterpret_cast<const unsigned char*>(Marker.data()),
			static_cast<int>(Marker.size())) == 1
		&& EVP_CipherUpdate(context, nullptr, &unused, header.data(), static_cast<int>(header.size())) == 1;
}

std::string Encode(std::span<const unsigned char> bytes)
{
	std::string frame(Marker);
	frame.reserve(Marker.size() + (4 * bytes.size() + 2) / 3);
	std::uint32_t bits = 0;
	unsigned int count = 0;
	for (const auto byte : bytes)
	{
		bits = (bits << 8) | byte;
		count += 8;
		while (count >= 6)
		{
			count -= 6;
			frame += Base64url[(bits >> count) & 63];
		}
	}
	if (count != 0)
		frame += Base64url[(bits << (6 - count)) & 63];
	return frame;
}

bool Decode(std::string_view payload, std::span<unsigned char, MaxWireSize> bytes, std::size_t& size)
{
	if (payload.size() % 4 == 1 || payload.size() * 6 / 8 > bytes.size())
		return false;
	std::uint32_t bits = 0;
	unsigned int count = 0;
	size = 0;
	for (const char character : payload)
	{
		const auto value = Base64url.find(character);
		if (value == std::string_view::npos)
			return false;
		bits = (bits << 6) | static_cast<std::uint32_t>(value);
		count += 6;
		if (count >= 8)
		{
			count -= 8;
			bytes[size++] = static_cast<unsigned char>(bits >> count);
		}
	}
	// RFC 4648 canonical encoding requires zero bits beyond the final byte.
	return (bits & ((std::uint32_t{1} << count) - 1)) == 0;
}

int HexValue(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

bool ValidPlaintext(std::string_view text)
{
	return !text.empty() && text.size() <= MaxPlaintextLength
		&& text.find_first_of(std::string_view("\0\r\n", 3)) == std::string_view::npos;
}
}

bool ParseKey(std::string_view hex, Key& key)
{
	if (hex.size() != key.size() * 2)
		return false;
	SensitiveBytes<32> parsed;
	for (std::size_t i = 0; i < parsed.bytes.size(); ++i)
	{
		const int high = HexValue(hex[i * 2]);
		const int low = HexValue(hex[i * 2 + 1]);
		if (high < 0 || low < 0)
			return false;
		parsed.bytes[i] = static_cast<unsigned char>((high << 4) | low);
	}
	key = parsed.bytes;
	return true;
}

bool Seal(const Key& key, std::string_view plaintext, std::string& frame)
{
	if (!ValidPlaintext(plaintext))
		return false;
	const ErrorQueueScope errors;
	std::array<unsigned char, MaxWireSize> wire{};
	const auto header = std::span(wire).first<HeaderSize>();
	if (!ReserveHeader(header))
		return false;

	SensitiveBytes<32> trafficKey;
	const CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!context || !DeriveTrafficKey(key, header, trafficKey.bytes)
		|| !InitCipher(context.get(), trafficKey.bytes, header, true))
		return false;

	auto* encrypted = wire.data() + HeaderSize;
	const int size = static_cast<int>(plaintext.size());
	int written = 0;
	int final = 0;
	if (EVP_EncryptUpdate(context.get(), encrypted, &written,
		reinterpret_cast<const unsigned char*>(plaintext.data()), size) != 1
		|| written != size || EVP_EncryptFinal_ex(context.get(), encrypted + written, &final) != 1
		|| final != 0 || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, TagSize, encrypted + size) != 1)
		return false;
	frame = Encode(std::span(wire).first(HeaderSize + size + TagSize));
	return true;
}

bool Open(const Key& key, std::string_view frame, std::string& plaintext)
{
	if (!frame.starts_with(Marker) || frame.size() > MaxFrameLength)
		return false;
	std::array<unsigned char, MaxWireSize> wire{};
	std::size_t wireSize = 0;
	if (!Decode(frame.substr(Marker.size()), wire, wireSize) || wireSize <= HeaderSize + TagSize)
		return false;
	const ErrorQueueScope errors;
	const auto header = std::span(wire).first<HeaderSize>();
	const int size = static_cast<int>(wireSize - HeaderSize - TagSize);

	SensitiveBytes<32> trafficKey;
	const CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!context || !DeriveTrafficKey(key, header, trafficKey.bytes)
		|| !InitCipher(context.get(), trafficKey.bytes, header, false))
		return false;

	SensitiveBytes<MaxPlaintextLength + EVP_MAX_BLOCK_LENGTH> clear;
	auto* encrypted = wire.data() + HeaderSize;
	int written = 0;
	int final = 0;
	if (EVP_DecryptUpdate(context.get(), clear.bytes.data(), &written, encrypted, size) != 1
		|| written != size || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, TagSize, encrypted + size) != 1
		|| EVP_DecryptFinal_ex(context.get(), clear.bytes.data() + written, &final) != 1 || final != 0)
		return false;
	const std::string_view text(reinterpret_cast<const char*>(clear.bytes.data()), size);
	if (!ValidPlaintext(text) || !AcceptCounter(trafficKey.bytes, header))
		return false;
	plaintext.assign(text);
	return true;
}

#ifdef FISH_AEAD_TEST
namespace test
{
// Test executables only. The production DLL always uses an OS-seeded session.
void SetSender(const Session& session, std::uint64_t counter)
{
	auto& state = Sender();
	const std::lock_guard lock(state.mutex);
	state.session = session;
	state.nextCounter = counter;
	state.initialized = true;
	state.exhausted = false;
}
}
#endif
}
