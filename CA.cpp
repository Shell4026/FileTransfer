#include "CA.h"
#include "PKI.h"
#include "SHA256.h"

#include <string>

CA::CA()
{
	rsa.SetPrivateKey("149275614295650212646224856599409889343612153197977726641730034661406136141284203664504101676174805306841980084317895961225204725911583320494331623348661876024425164329407408823961815963067126531492837014168038126177260635723783172871192755501807296087498277143098859254717644074274546978328490284654469919447853");
	rsa.SetPublicKey(RSA::PublicKey{ "345875055120877779253867365280379208694089081991722335899560236224308783605845602105731140588703136482040051220998477907400256041084229665025172762927390963759357009146922635545802337230105106041727020861868015855575812477197693802951423534652140890280538926540369142320084422084191734785034233269710441659655677", 65537 });
}

void CA::Signature(PKI& pki)
{
	std::string m = pki.version + pki.ip + pki.pubKey.n.toString() + pki.pubKey.e.toString();

	SHA256 sha;
	sha.update(m);
	std::array<uint8_t, 32> hashArray{ sha.digest() };
	std::string tmp(32, '0');
	for (int i = 0; i < 32; ++i)
		tmp[i] = hashArray[i] + '0';
	InfInt hash{ tmp };

	pki.signature = rsa.EncryptOrDecrypt(hash, rsa.GetPrivateKey(), rsa.GetPublicKey());
}

bool CA::Verify(const PKI& pki)
{
	std::string m = pki.ip + pki.pubKey.n.toString() + pki.pubKey.e.toString();

	SHA256 sha;
	sha.update(m);
	std::array<uint8_t, 32> hashArray{ sha.digest() };
	std::string tmp(32, '0');
	for (int i = 0; i < 32; ++i)
		tmp[i] = hashArray[i] + '0';
	InfInt hash{ tmp };

	return hash == rsa.EncryptOrDecrypt(pki.signature, rsa.GetPublicKey());
}

auto CA::GetInstance() -> CA*
{
	if (instance == nullptr)
		instance = new CA{};

	return instance;
}
