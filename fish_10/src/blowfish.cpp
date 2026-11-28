#include "fish-internal.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <openssl/evp.h>

namespace
{
constexpr size_t BlockSize = 8;
constexpr size_t EncodedWordSize = 6;
constexpr size_t EncodedBlockSize = EncodedWordSize * 2;
constexpr size_t MaxKeySize = 72;
constexpr std::string_view Alphabet = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

using Cipher = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

bool InitCipher(EVP_CIPHER_CTX* a_ctx, const std::string& a_key, int a_encrypt)
{
	if (!a_ctx || a_key.empty() || a_key.size() > MaxKeySize)
		return false;

	const Cipher l_cipher(EVP_CIPHER_fetch(nullptr, "BF-ECB", "provider=legacy"), EVP_CIPHER_free);
	return l_cipher
		&& EVP_CipherInit_ex2(a_ctx, l_cipher.get(), nullptr, nullptr, a_encrypt, nullptr)
		&& EVP_CIPHER_CTX_set_key_length(a_ctx, static_cast<int>(a_key.size()))
		&& EVP_CIPHER_CTX_set_padding(a_ctx, 0)
		&& EVP_CipherInit_ex2(a_ctx, nullptr,
			reinterpret_cast<const unsigned char*>(a_key.data()), nullptr, a_encrypt, nullptr);
}

void EncodeWord(const unsigned char* a_word, std::string& ar_encoded)
{
	std::uint32_t l_word = 0;
	for (size_t i = 0; i < 4; ++i)
		l_word = (l_word << 8) | a_word[i];

	for (size_t i = 0; i < EncodedWordSize; ++i)
	{
		ar_encoded += Alphabet[l_word & 63];
		l_word >>= 6;
	}
}

void DecodeWord(std::string_view a_encoded, unsigned char* ar_word)
{
	// The sixth character supplies the top two bits of each 32-bit word.
	std::uint32_t l_word = 0;
	for (size_t i = 0; i < EncodedWordSize; ++i)
		l_word |= static_cast<std::uint32_t>(Alphabet.find(a_encoded[i])) << (6 * i);

	for (size_t i = 4; i > 0; --i)
	{
		ar_word[i - 1] = static_cast<unsigned char>(l_word);
		l_word >>= 8;
	}
}

bool TransformBlock(EVP_CIPHER_CTX* a_ctx, const unsigned char* a_in, unsigned char* ar_out)
{
	int l_size = 0;
	return EVP_CipherUpdate(a_ctx, ar_out, &l_size, a_in, static_cast<int>(BlockSize)) && l_size == BlockSize;
}

bool FinishCipher(EVP_CIPHER_CTX* a_ctx)
{
	unsigned char l_out[EVP_MAX_BLOCK_LENGTH];
	int l_size = 0;
	return EVP_CipherFinal_ex(a_ctx, l_out, &l_size) && l_size == 0;
}
}

bool blowfish_encrypt(const std::string& a_in, std::string& ar_out, const std::string& a_key)
{
	const CipherContext l_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!InitCipher(l_ctx.get(), a_key, 1))
		return false;

	std::string l_encoded;
	for (size_t l_offset = 0; l_offset < a_in.size();)
	{
		// FiSH zero-pads the final plaintext block before encryption.
		unsigned char l_plain[BlockSize] = {};
		const size_t l_size = std::min(BlockSize, a_in.size() - l_offset);
		std::memcpy(l_plain, a_in.data() + l_offset, l_size);
		l_offset += l_size;

		unsigned char l_encrypted[2 * BlockSize];
		if (!TransformBlock(l_ctx.get(), l_plain, l_encrypted))
			return false;

		// FiSH places the right 32-bit word before the left word on the wire.
		EncodeWord(l_encrypted + BlockSize / 2, l_encoded);
		EncodeWord(l_encrypted, l_encoded);
	}

	if (!FinishCipher(l_ctx.get()))
		return false;

	ar_out.swap(l_encoded);
	return true;
}

int blowfish_decrypt(const std::string& a_in, std::string& ar_out, const std::string& a_key)
{
	const size_t l_tailSize = a_in.size() % EncodedBlockSize;
	const size_t l_completeSize = a_in.size() - l_tailSize;
	const std::string_view l_encoded(a_in.data(), l_completeSize);
	// Only complete blocks are recoverable when an IRC line is truncated.
	if (l_encoded.empty() || l_encoded.find_first_not_of(Alphabet) != std::string_view::npos)
		return -1;

	const CipherContext l_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!InitCipher(l_ctx.get(), a_key, 0))
		return -1;

	std::string l_plain;
	for (size_t l_offset = 0; l_offset < l_completeSize; l_offset += EncodedBlockSize)
	{
		unsigned char l_encrypted[BlockSize];
		DecodeWord(l_encoded.substr(l_offset, EncodedWordSize), l_encrypted + BlockSize / 2);
		DecodeWord(l_encoded.substr(l_offset + EncodedWordSize, EncodedWordSize), l_encrypted);

		unsigned char l_block[2 * BlockSize];
		if (!TransformBlock(l_ctx.get(), l_encrypted, l_block))
			return -1;
		l_plain.append(reinterpret_cast<const char*>(l_block), BlockSize);
	}

	if (!FinishCipher(l_ctx.get()))
		return -1;

	// Publish the result after reading the input so callers can reuse its storage.
	remove_bad_chars(l_plain);
	ar_out.swap(l_plain);
	return l_tailSize ? 1 : 0;
}
