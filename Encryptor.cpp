#include "Encryptor.h"
#include "XXTEA.h"
#include "AES.h"

#include <stdexcept>

auto Encryptor::BytesToWords(const std::vector<uint8_t>& bytes) -> std::vector<uint32_t>
{
    std::vector<uint32_t> words;
    words.reserve(bytes.size() / 4);
    for (int i = 0; i < bytes.size(); i += 4)
    {
        uint32_t word = 0;
        for (int j = 0; j < 4; ++j)
        {
            if (i + j < bytes.size())
                word |= bytes[i + j] << j * 8;
        }
        words.push_back(word);
    }
    return words;
}

auto Encryptor::WordsToBytes(const std::vector<uint32_t>& words) -> std::vector<uint8_t>
{
    std::vector<uint8_t> bytes;
    bytes.reserve(words.size() * 4);

    for (int i = 0; i < words.size(); ++i)
    {
        uint32_t word = words[i];
        for (int j = 0; j < 4; ++j)
        {
            bytes.push_back((word >> j * 8) & 0xff);
        }
    }

    return bytes;
}

void Encryptor::AddPKCS7Padding(std::vector<uint8_t>& data, std::size_t blockSize)
{
    size_t padding = blockSize - (data.size() % blockSize);
    if (padding == 0) 
        padding = blockSize;
    data.insert(data.end(), padding, static_cast<uint8_t>(padding));
}

void Encryptor::RemovePKCS7Padding(std::vector<uint8_t>& data, std::size_t blockSize)
{
    if (data.empty() || data.size() % blockSize != 0)
        throw std::invalid_argument(u8"올바르지 않은 패딩1");

    uint8_t padding = data.back();
    if (padding == 0 || padding > blockSize)
        throw std::invalid_argument(u8"올바르지 않은 패딩2");

    for (size_t i = data.size() - padding; i < data.size(); ++i) 
    {
        if (data[i] != padding)
            throw std::invalid_argument(u8"올바르지 않은 패딩3");
    }

    data.erase(data.end() - padding, data.end());
}

auto Encryptor::Encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) const -> std::vector<uint8_t>
{
    if (algorithm == Algorithm::XXTEA)
        return XXTEA::Encrypt(input, key);
    else
        return AES::Encrypt(input, key);
}

auto Encryptor::Decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) const -> std::vector<uint8_t>
{
    if (algorithm == Algorithm::XXTEA)
        return XXTEA::Decrypt(input, key);
    else
        return AES::Decrypt(input, key);
}
