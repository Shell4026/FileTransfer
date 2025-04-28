#pragma once

#include <vector>
#include <cstdint>

class Encryptor
{
public:
	enum class Algorithm
	{
		XXTEA,
		AES128
	} algorithm;
public:
	static auto BytesToWords(const std::vector<uint8_t>& bytes) -> std::vector<uint32_t>;
	static auto WordsToBytes(const std::vector<uint32_t>& words) -> std::vector<uint8_t>;
	static void AddPKCS7Padding(std::vector<uint8_t>& data, std::size_t blockSize);
	static void RemovePKCS7Padding(std::vector<uint8_t>& data, std::size_t blockSize);
	auto Encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) const -> std::vector<uint8_t>;
	auto Decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) const -> std::vector<uint8_t>;
};

