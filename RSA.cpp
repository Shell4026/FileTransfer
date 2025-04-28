#include "RSA.h"

#include <algorithm>
#include <numeric>
#include <random>
#include <iostream>
#include <limits>
#include <thread>
#include <mutex>
#include <chrono>

bool RSA::IsPrime(const InfInt& num)
{
    for(int i = 0; i < 15; ++i)
    {
        if (num == PRIMES[i])
            return true;
        if (num % PRIMES[i] == 0)
            return false;
        if (!MillerRabin(num, PRIMES[i]))
            return false;
    }
    return true;
}

auto RSA::ModExp(const InfInt& base, const InfInt& exp, const InfInt& mod) -> InfInt
{
    // base^exp % mod
    // 2진 제곱법 (Binary Exponentiation) 
    InfInt result = 1;
    InfInt newBase = base;
    InfInt newExp = exp;

    while (newExp > 0)
    {
        if (newExp % 2 == 1)
            result = (result * newBase) % mod;

        newBase = (newBase * newBase) % mod;
        newExp /= 2;
    }

    return result;
}

auto RSA::ModInverse(const InfInt& e, const InfInt& phi) -> InfInt
{
    InfInt t = 0, new_t = 1;
    InfInt r = phi, new_r = e;

    while (new_r != 0) 
    {
        InfInt quotient{ r / new_r };
        InfInt temp_t{ t };
        t = new_t;
        new_t = temp_t - quotient * new_t;

        InfInt temp_r{ std::move(r) };
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (t < 0)
        t += phi;

    return t;
}

bool RSA::MillerRabin(const InfInt& n, uint32_t prime)
{
    InfInt k = n - 1;

    while (true) 
    {
        InfInt d = ModExp(prime, k, n);
        if (k % 2 == 1) 
            return (d == 1 || d == n - 1);
        if (d == n - 1) 
            return true;
        k /= 2;
    }
}

void RSA::CreateRSA()
{
    std::random_device device{};
    std::mt19937_64 seed{ device() };
   
    std::uniform_int_distribution<uint64_t> rnd{ 0, std::numeric_limits<uint64_t>::max() };
    InfInt p{ 0 }, q{0};

    constexpr int SIZE = 1024; // 소수 비트
    std::string pstr{}, qstr{};
    for (int i = 0; i < SIZE / 128; ++i)
        pstr += std::to_string(rnd(seed));
    for (int i = 0; i < SIZE / 128; ++i)
        qstr += std::to_string(rnd(seed));
    p = pstr;
    q = qstr;
    
    if (p % 2 == 0)
        ++p;
    if (q % 2 == 0)
        ++q;

    uint32_t threadCount = std::thread::hardware_concurrency();
    uint32_t threadPrimeCount = threadCount / 3;
    std::cout << "스레드 수: " << threadCount << '\n';

    std::vector<std::thread> thrP(threadPrimeCount);
    std::vector<std::thread> thrQ(threadPrimeCount);
    std::atomic_bool findP, findQ = false;
    std::mutex muP, muQ;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < threadPrimeCount; ++i)
    {
        thrP[i] = std::thread([&, i]
            {
                InfInt testP{ p + i * 2 };
                while (!IsPrime(testP))
                {
                    if (findP.load(std::memory_order::memory_order_acquire))
                        break;
                    testP += 2 * threadPrimeCount;
                }
                if (!findP.load(std::memory_order::memory_order_acquire))
                {
                    findP.store(true, std::memory_order::memory_order_release);
                    if (muP.try_lock())
                    {
                        p = std::move(testP);
                        muP.unlock();
                    }
                }
            }
        );
    }
    for (int i = 0; i < threadPrimeCount; ++i)
    {
        thrQ[i] = std::thread([&, i]
            {
                InfInt testQ{ q + i * 2 };
                while (!IsPrime(testQ))
                {
                    if (findQ.load(std::memory_order::memory_order_acquire))
                        break;
                    testQ += 2 * threadPrimeCount;
                }
                if (!findQ.load(std::memory_order::memory_order_acquire))
                {
                    findQ.store(true, std::memory_order::memory_order_release);
                    if (muQ.try_lock())
                    {
                        q = std::move(testQ);
                        muQ.unlock();
                    }
                }
            }
        );
    }
    for (int i = 0; i < threadPrimeCount; ++i)
        thrP[i].join();
    for (int i = 0; i < threadPrimeCount; ++i)
        thrQ[i].join();

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "소수 구하는데 걸린 시간: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << '\n';

    pubkey.n = p * q;
    pubkey.e = 65537;
    prKey = ModInverse(pubkey.e, (p - 1) * (q - 1));

    std::cout << "(n, e, d, phi): " << pubkey.n << ", " << pubkey.e << ", " << prKey << ", " << (p - 1) * (q - 1) << '\n';
}

auto RSA::GetPublicKey() const -> PublicKey
{
    return pubkey;
}

auto RSA::GetPrivateKey() const -> InfInt
{
    return prKey;
}

void RSA::SetPrivateKey(InfInt&& key) noexcept
{
    prKey = std::move(key);
}

void RSA::SetPublicKey(const PublicKey& pubKey)
{
    this->pubkey = pubKey;
}

auto RSA::EncryptOrDecrypt(const InfInt& plainText, const PublicKey& _pubKey) -> InfInt
{
    return ModExp(plainText, _pubKey.e, _pubKey.n);
}

auto RSA::EncryptOrDecrypt(const InfInt& plainText, const InfInt& prKey, const PublicKey& pubKey) -> InfInt
{
    return ModExp(plainText, prKey, pubKey.n);
}

void RSA::Save(const std::string& dir)
{
    FILE* file;
    file = fopen(dir.c_str(), "w");
    if (file == nullptr)
    {
        std::cout << "키 저장 오류\n";
        return;
    }

    fputs(prKey.toString().c_str(), file);
    fputc('\n', file);
    fputs(pubkey.n.toString().c_str(), file);
    fputc('\n', file);
    fputs(pubkey.e.toString().c_str(), file);

    fclose(file);
}

bool RSA::Load(const std::string& dir)
{
    FILE* file;
    file = fopen(dir.c_str(), "r");
    if (file == nullptr)
    {
        std::cout << "키 불러오기 오류\n";
        return false;
    }

    char buf[1000] = { 0 };
    fgets(buf, 1000, file);
    buf[std::strlen(buf) - 1] = 0;
    prKey = buf;

    fgets(buf, 1000, file);
    buf[std::strlen(buf) - 1] = 0;
    pubkey.n = buf;

    fgets(buf, 1000, file);
    pubkey.e = buf;

    fclose(file);
    return true;
}
