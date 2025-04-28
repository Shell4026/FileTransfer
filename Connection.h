#pragma once
#include "RSA.h"
#include "Encryptor.h"

#include <SFML/Network.hpp>

#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <atomic>

class PKI;
class Encryptor;

class Connection
{
private:
	enum PacketType 
	{
		PublicKey = 1,
		PublicKeyACK = 2,
		EncryptedMessage = 3,
		FileTransferReqeust = 4,
		FileTransferRequestACK = 5,
		FileReceived
	};

	sf::TcpListener server{};
	sf::TcpSocket client{};

	RSA rsa{};
	RSA targetRSA{};

	std::unique_ptr<PKI> pki;

	Encryptor encryptor;
	std::vector<uint8_t> key;

	struct SendFile
	{
		std::string name;
		std::vector<uint8_t> data;
		std::size_t originalSize = 0;
		std::size_t size = 0; // 암호화 된 후 크기
		std::size_t sendedBytes = 0;
		std::size_t chunkBytes = 0; // 부분적으로 보낸 경우
		int cipherAlgorithm = 0;
		bool bSend = false;
	} sendFile;
	friend auto operator<<(sf::Packet& packet, const Connection::SendFile& file) -> sf::Packet&;

	struct RecievedFile
	{
		std::string name;
		std::vector<uint8_t> data;
		std::size_t originalSize = 0;
		std::size_t size = 0; // 암호화 된 후 크기
		std::size_t receivedBytes = 0;
		std::size_t chunkBytes = 0; // 부분적으로 받은 경우
		int cipherAlgorithm = 0;
		bool bReceived = false;
	} receivedFile;
	friend auto operator>>(sf::Packet& packet, Connection::RecievedFile& file) -> sf::Packet&;

	bool bConnected = false;
	bool bSendState = false;
	bool bReceiveState = false;
	bool bClientFileReceving = false;
	std::atomic_bool bGeneratingRSA = false;
public:
	const std::string myIP;
private:
	void CreatePKI();
	void GenerateKey();
	void ProcessPacket(sf::Packet& packet);
	void SendingProcess();
	void RecevingProcess();
public:
	Connection(unsigned short port);
	~Connection();

	void SetPort(unsigned short port);
	bool Connect(const std::string& ip, unsigned short port);

	void Update();

	bool SendData(const std::vector<uint8_t>& data, const std::string& name, const Encryptor* encryptor = nullptr);

	bool IsConnected() const;
	bool IsFileReceived() const;
	bool IsClientFileReceiving() const;
	bool IsGeneratingRSA() const;

	auto GetRecievedFile() const -> const std::vector<uint8_t>&;
	auto GetRecievedFileName() const -> const std::string&;
	auto GetRecievedSize() const -> std::size_t;
};

inline auto operator<<(sf::Packet& packet, const Connection::SendFile& file) -> sf::Packet&
{
	return packet << file.name << file.originalSize << file.size << file.cipherAlgorithm;
}
inline auto operator>>(sf::Packet& packet, Connection::RecievedFile& file) -> sf::Packet&
{
	return packet >> file.name >> file.originalSize >> file.size >> file.cipherAlgorithm;
}
