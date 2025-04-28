#pragma once

#include "RSA.h"
class PKI;

// 가상의 CA
class CA
{
private:
	RSA rsa;

	inline static CA* instance = nullptr;
protected:
	CA();
public:
	void Signature(PKI& pki);
	bool Verify(const PKI& pki);

	static auto GetInstance() -> CA*;
};