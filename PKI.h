#pragma once
#include "RSA.h"

#include <string>
#include <optional>

class PKI
{
	friend class CA;
private:
	InfInt signature;
public:
	const std::string version = "1";
	const std::string ip;
	const RSA::PublicKey pubKey;
public:
	PKI(const std::string& version, const std::string& ip, const RSA::PublicKey& pubKey);

	void Save(const std::string& dir);
	static auto Load(const std::string& dir) -> std::optional<PKI>;

	void SetSignature(InfInt&& signature) noexcept;
	auto GetSignature() const -> const InfInt&;
};