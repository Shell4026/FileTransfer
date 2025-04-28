#pragma once

#include "Infint.h"

#include <cstdint>

class RSA
{
public:
	struct PublicKey
	{
		InfInt n, e;
	};
private:
	PublicKey pubkey; // ���� Ű
	InfInt prKey{0}; // ����Ű

	static constexpr uint32_t PRIMES[20] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73 };//, 73, 79, 83, 89, 97 };
private:
	bool IsPrime(const InfInt& num);
	static auto ModExp(const InfInt& base, const InfInt& exp, const InfInt& mod) -> InfInt; // base^exp % mod
	auto ModInverse(const InfInt& e, const InfInt& phi) -> InfInt;
	bool MillerRabin(const InfInt& n, uint32_t prime); // �з�-��� �Ҽ� �Ǻ���
public:
	void CreateRSA();

	auto GetPublicKey() const -> PublicKey;
	auto GetPrivateKey() const -> InfInt;

	void SetPrivateKey(InfInt&& key) noexcept;
	void SetPublicKey(const PublicKey& pubKey);

	static auto EncryptOrDecrypt(const InfInt& text, const PublicKey& pubKey) -> InfInt;
	static auto EncryptOrDecrypt(const InfInt& text, const InfInt& prKey, const PublicKey& pubKey) -> InfInt;

	void Save(const std::string& dir);
	bool Load(const std::string& dir);
};