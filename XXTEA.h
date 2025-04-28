#pragma once

#include <vector>
#include <stdint.h>
class XXTEA
{
private:
	static constexpr uint32_t DELTA = 0x9E3779B9;
	static constexpr int BLOCK_SIZE = 16;
public:
	static auto Encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>;
	static auto Decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>;
};