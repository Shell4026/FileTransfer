#include "AES.h"
#include "Encryptor.h"

#include <stdexcept>
#include <algorithm>

auto AES::KeyExpansion(const std::vector<uint8_t>& key)->std::array<std::array<uint8_t, KEY_SIZE>, ROUNDS + 1>
{
    if (key.size() != KEY_SIZE)
        throw std::runtime_error("Invalid AES key size");

    std::array<std::array<uint8_t, KEY_SIZE>, ROUNDS + 1> keys;

    // 초기 키를 keys[0]에 복사
    std::copy(key.begin(), key.end(), keys[0].begin());

    // 나머지 라운드 키 생성
    for (int i = 1; i <= ROUNDS; ++i)
    {
        uint8_t temp[4];
        // 이전 라운드 키의 마지막 워드를 가져옴
        temp[0] = keys[i - 1][12];
        temp[1] = keys[i - 1][13];
        temp[2] = keys[i - 1][14];
        temp[3] = keys[i - 1][15];

        // RotWord
        {
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
        }

        // SubWord
        for (int j = 0; j < 4; ++j)
            temp[j] = sbox[temp[j]];

        // Rcon 적용
        temp[0] ^= rcon[i];

        // 현재 라운드 키의 첫 번째 워드 계산
        for (int j = 0; j < 4; ++j)
            keys[i][j] = keys[i - 1][j] ^ temp[j];

        // 나머지 워드 계산
        for (int j = 4; j < 16; ++j)
            keys[i][j] = keys[i - 1][j] ^ keys[i][j - 4];
    }

    return keys;
}


void AES::AddRoundKey(State& state, const std::array<uint8_t, KEY_SIZE>& roundKey)
{
    for (int i = 0; i < 4; i++) 
    {
        for (int j = 0; j < 4; j++) 
        {
            state[i][j] ^= roundKey[i * 4 + j];
        }
    }
}

void AES::SubBytes(State& state, bool inverse)
{
    for (int i = 0; i < 4; i++) 
    {
        for (int j = 0; j < 4; j++) 
        {
            if (!inverse)
                state[i][j] = sbox[state[i][j]];
            else
                state[i][j] = rsbox[state[i][j]];
        }
    }
}

void AES::ShiftRows(State& state, bool inverse)
{
    uint8_t temp;
    if (!inverse)
    {
        // 행 0: 이동 없음

        // 행 1: 왼쪽으로 1칸 이동
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // 행 2: 왼쪽으로 2칸 이동
        std::swap(state[2][0], state[2][2]);
        std::swap(state[2][1], state[2][3]);

        // 행 3: 왼쪽으로 3칸 이동 (오른쪽으로 1칸 이동과 동일)
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
    }
    else
    {
        // 행 0: 이동 없음

        // 행 1: 오른쪽으로 1칸 이동
        temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // 행 2: 오른쪽으로 2칸 이동
        std::swap(state[2][0], state[2][2]);
        std::swap(state[2][1], state[2][3]);

        // 행 3: 오른쪽으로 3칸 이동 (왼쪽으로 1칸 이동과 동일)
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }
}


auto AES::Gmul(uint8_t a, uint8_t b) -> uint8_t
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) 
    {
        if (b & 1)
            p ^= a;
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B; // AES의 감소 다항식
        b >>= 1;
    }
    return p;
}

void AES::MixColumns(State& state, bool inverse)
{
    uint8_t temp[4];
    if (!inverse)
    {
        for (int i = 0; i < 4; i++)
        {
            temp[0] = (uint8_t)(Gmul(0x02, state[0][i]) ^ Gmul(0x03, state[1][i]) ^ state[2][i] ^ state[3][i]);
            temp[1] = (uint8_t)(state[0][i] ^ Gmul(0x02, state[1][i]) ^ Gmul(0x03, state[2][i]) ^ state[3][i]);
            temp[2] = (uint8_t)(state[0][i] ^ state[1][i] ^ Gmul(0x02, state[2][i]) ^ Gmul(0x03, state[3][i]));
            temp[3] = (uint8_t)(Gmul(0x03, state[0][i]) ^ state[1][i] ^ state[2][i] ^ Gmul(0x02, state[3][i]));
            state[0][i] = temp[0];
            state[1][i] = temp[1];
            state[2][i] = temp[2];
            state[3][i] = temp[3];
        }
    }
    else
    {
        for (int i = 0; i < 4; i++)
        {
            temp[0] = (uint8_t)(Gmul(0x0E, state[0][i]) ^ Gmul(0x0B, state[1][i]) ^ Gmul(0x0D, state[2][i]) ^ Gmul(0x09, state[3][i]));
            temp[1] = (uint8_t)(Gmul(0x09, state[0][i]) ^ Gmul(0x0E, state[1][i]) ^ Gmul(0x0B, state[2][i]) ^ Gmul(0x0D, state[3][i]));
            temp[2] = (uint8_t)(Gmul(0x0D, state[0][i]) ^ Gmul(0x09, state[1][i]) ^ Gmul(0x0E, state[2][i]) ^ Gmul(0x0B, state[3][i]));
            temp[3] = (uint8_t)(Gmul(0x0B, state[0][i]) ^ Gmul(0x0D, state[1][i]) ^ Gmul(0x09, state[2][i]) ^ Gmul(0x0E, state[3][i]));
            state[0][i] = temp[0];
            state[1][i] = temp[1];
            state[2][i] = temp[2];
            state[3][i] = temp[3];
        }
    }
}


auto AES::Encrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>
{
    std::vector<uint8_t> inputBlocks{ input };

    int n = (input.size() / BLOCK_SIZE) + 1; // PKCS7 패딩에선 사이즈가 블록 길이와 같아도 패딩을 추가 하기 때문에 +1
    Encryptor::AddPKCS7Padding(inputBlocks, BLOCK_SIZE);

    std::vector<uint8_t> output(inputBlocks.size(), 0);

    std::array<std::array<uint8_t, KEY_SIZE>, ROUNDS + 1> roundKeys{ KeyExpansion(key) }; // 16바이트 x 11

    for (int b = 0; b < n; ++b)
    {
        int blockPos = b * BLOCK_SIZE;
        std::vector<uint8_t> block(BLOCK_SIZE, 0);
        std::copy(inputBlocks.begin() + blockPos, inputBlocks.begin() + blockPos + BLOCK_SIZE, block.begin()); // n번째 블록을 복사해옴

        State state;
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                state[i][j] = block[i * 4 + j];
        }

        AddRoundKey(state, roundKeys[0]);
        for (int round = 1; round <= ROUNDS; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            if (round != ROUNDS)
                MixColumns(state);
            AddRoundKey(state, roundKeys[round]);
        }

        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                output[blockPos + i * 4 + j] = state[i][j];
        }
    }

    return output;
}

auto AES::Decrypt(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key) -> std::vector<uint8_t>
{
    if (input.size() % BLOCK_SIZE != 0)
        throw std::invalid_argument(u8"AES 복호화 블록 사이즈가 다릅니다.");

    int n = input.size() / BLOCK_SIZE;
    std::vector<uint8_t> output(input.size());

    std::array<std::array<uint8_t, KEY_SIZE>, ROUNDS + 1> roundKeys{ KeyExpansion(key) };

    for (int b = 0; b < n; ++b)
    {
        State state;
        int blockPos = b * BLOCK_SIZE;
        std::vector<uint8_t> block(BLOCK_SIZE, 0);
        std::copy(input.begin() + blockPos, input.begin() + blockPos + BLOCK_SIZE, block.begin()); // n번째 블록을 복사해옴

        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                state[i][j] = block[i * 4 + j];
        }

        AddRoundKey(state, roundKeys[ROUNDS]);

        for (int round = ROUNDS - 1; round >= 0; --round)
        {
            ShiftRows(state, true);
            SubBytes(state, true);
            AddRoundKey(state, roundKeys[round]);
            if (round != 0)
                MixColumns(state, true);
        }

        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
                output[blockPos + i * 4 + j] = state[i][j];
        }
    }

    Encryptor::RemovePKCS7Padding(output, BLOCK_SIZE);
    return output;
}

