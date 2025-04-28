#include "XXTEA.h"
#include "Encryptor.h"

#include <execution>
#include <iostream>

auto XXTEA::Encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>
{
    if (key.size() != 16)
        throw std::runtime_error(u8"XXTEA의 키 사이즈는 128비트여야 합니다!");

    std::vector<uint8_t> inputBlocks{ input };
    int n = (input.size() / BLOCK_SIZE) + 1; // PKCS7 패딩에선 사이즈가 블록 길이와 같아도 패딩을 추가 하기 때문에 +1
    Encryptor::AddPKCS7Padding(inputBlocks, BLOCK_SIZE);

    std::vector<uint8_t> output(inputBlocks.size(), 0);

    std::vector<uint32_t> keyWords{ Encryptor::BytesToWords(key) };
    for (int b = 0; b < n; ++b)
    {
        int blockPos = b * BLOCK_SIZE;
        std::vector<uint8_t> block(BLOCK_SIZE, 0);
        std::copy(inputBlocks.begin() + blockPos, inputBlocks.begin() + blockPos + BLOCK_SIZE, block.begin()); // n번째 블록을 복사해옴

        std::vector<uint32_t> v{ Encryptor::BytesToWords(block) };

        int n = v.size();
        uint32_t y, z, sum = 0;
        unsigned p, rounds, e;

        rounds = 6 + 52 / n;
        z = v[n - 1];
        while (rounds-- > 0)
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                v[p] += ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                z = v[p];
            }
            y = v[0];
            v[n - 1] += ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(n - 1 & 3) ^ e] ^ z));
            z = v[n - 1];
        }

        auto encBytes = Encryptor::WordsToBytes(v);
        for (int i = 0; i < BLOCK_SIZE; ++i)
            output[blockPos + i] = encBytes[i];
    }

    return output;
}

auto XXTEA::Decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>
{
    if (key.size() != 16)
        throw std::runtime_error(u8"XXTEA의 키 사이즈는 128비트여야 합니다!");

    int n = input.size() / BLOCK_SIZE;
    std::vector<uint8_t> output(input.size());

    std::vector<uint32_t> keyWords{ Encryptor::BytesToWords(key) };
    for (int b = 0; b < n; ++b)
    {
        int blockPos = b * BLOCK_SIZE;
        std::vector<uint8_t> block(BLOCK_SIZE, 0);
        std::copy(input.begin() + blockPos, input.begin() + blockPos + BLOCK_SIZE, block.begin()); // n번째 블록을 복사해옴

        std::vector<uint32_t> v{ Encryptor::BytesToWords(block) };

        uint32_t y, z, sum;
        unsigned p, rounds, e;
        int words = v.size();

        rounds = 6 + 52 / words;
        sum = rounds * DELTA;
        y = v[0];
        while (rounds-- > 0) {
            e = (sum >> 2) & 3;
            for (p = words - 1; p > 0; p--) {
                z = v[p - 1];
                v[p] -= ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                y = v[p];
            }
            z = v[words - 1];
            v[0] -= ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(0 & 3) ^ e] ^ z));
            y = v[0];
            sum -= DELTA;
        }

        auto decBytes = Encryptor::WordsToBytes(v);
        for (int i = 0; i < BLOCK_SIZE; ++i)
        {
            output[blockPos + i] = decBytes[i];
        }
    }

    Encryptor::RemovePKCS7Padding(output, BLOCK_SIZE);

    return output;
}
