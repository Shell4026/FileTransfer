#include "PKI.h"

#include <iostream>
#include <cstdio>

PKI::PKI(const std::string& version, const std::string& ip, const RSA::PublicKey& pubKey) :
	version(version), ip(ip), pubKey(pubKey)
{
}

void PKI::Save(const std::string& dir)
{
	FILE* file;
	file = fopen(dir.c_str(), "w");
	if (file == nullptr)
	{
		std::cout << "인증서 저장 오류\n";
		return;
	}
	
	fputs(version.c_str(), file);
	fputc('\n', file);
	fputs(ip.c_str(), file);
	fputc('\n', file);
	fputs(pubKey.n.toString().c_str(), file);
	fputc('\n', file);
	fputs(pubKey.e.toString().c_str(), file);
	fputc('\n', file);
	fputs(signature.toString().c_str(), file);

	fclose(file);
}

auto PKI::Load(const std::string& dir) -> std::optional<PKI>
{
	FILE* file;
	file = fopen(dir.c_str(), "r");
	if (file == nullptr)
	{
		std::cout << "인증서 불러오기 오류\n";
		return {};
	}

	char buf[1000] = { 0 };

	fgets(buf, 1000, file);
	buf[std::strlen(buf) - 1] = 0;
	std::string version{ buf };

	fgets(buf, 1000, file);
	buf[std::strlen(buf) - 1] = 0;
	std::string ip{ buf };

	fgets(buf, 1000, file);
	buf[std::strlen(buf) - 1] = 0;
	RSA::PublicKey pubKey;
	pubKey.n = buf;

	fgets(buf, 1000, file);
	buf[std::strlen(buf) - 1] = 0;
	pubKey.e = buf;

	PKI pki{ version, ip, pubKey };
	fgets(buf, 1000, file);
	pki.signature = buf;

	fclose(file);

	return pki;
}

void PKI::SetSignature(InfInt&& signature) noexcept
{
	this->signature = std::move(signature);
}

auto PKI::GetSignature() const -> const InfInt&
{
	return signature;
}
