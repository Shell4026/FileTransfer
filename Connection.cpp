#include "Connection.h"
#include "CA.h"
#include "PKI.h"
#include "ErrorMessage.h"

#include <iostream>
#include <exception>
#include <random>
#include <array>
#include <future>

void Connection::CreatePKI()
{
	std::cout << "인증서 생성중...\n";
	pki = std::make_unique<PKI>("1", myIP, rsa.GetPublicKey());
	CA::GetInstance()->Signature(*pki);
	pki->Save("PKI");
	std::cout << "인증서 생성 완료\n";
}

void Connection::GenerateKey()
{
	key.resize(16);
	
	std::random_device device{};
	std::mt19937 gen{ device() };

	std::uniform_int_distribution rnd{ 0, 255 };
	for (auto& k : key)
		k = rnd(gen);
}

void Connection::ProcessPacket(sf::Packet& packet)
{
	int type;
	packet >> type;

	sf::Packet sendPacket;
	switch (type)
	{
	case PacketType::PublicKey: // 클라이언트에게서 공개키를 받았음
	{
		std::string version, ip, n, e, signature;
		packet >> version >> ip >> n >> e >> signature;

		RSA::PublicKey targetPublicKey{};
		targetPublicKey.n = n;
		targetPublicKey.e = e;
		targetRSA.SetPublicKey(targetPublicKey);

		PKI targetPKI{ version, ip, targetPublicKey };
		targetPKI.SetSignature(signature);
		bool verify = CA::GetInstance()->Verify(targetPKI);
		if (!verify)
		{
			std::cout << "유효하지 않은 인증서\n";
			client.disconnect();
			bConnected = false;
			return;
		}
		RSA::PublicKey pubKey{ rsa.GetPublicKey() };
		
		sendPacket << PacketType::PublicKeyACK << pki->version << pki->ip << pki->pubKey.n.toString() << pki->pubKey.e.toString() << pki->GetSignature().toString();
		client.send(sendPacket);
		break;
	}
	case PacketType::PublicKeyACK: // 서버에게서 공개키를 받았음, 서로 공개키 교환 완료
	{
		std::string version, ip, n, e, signature;
		packet >> version >> ip >> n >> e >> signature;

		RSA::PublicKey targetPublicKey{};
		targetPublicKey.n = n;
		targetPublicKey.e = e;
		targetRSA.SetPublicKey(targetPublicKey);

		PKI targetPKI{ version, ip, targetPublicKey };
		targetPKI.SetSignature(signature);
		bool verify = CA::GetInstance()->Verify(targetPKI);
		if (!verify)
		{
			ErrorMessage::Show(u8"유효하지 않은 인증서");
			client.disconnect();
			bConnected = false;
			return;
		}

		GenerateKey(); // 키 생성
		auto keyWords = Encryptor::BytesToWords(key);

		sendPacket << PacketType::EncryptedMessage;
		// 키 전송
		std::cout << "Send key: ";
		for (int i = 0; i < 4; ++i)
		{
			std::cout << keyWords[i] << ' ';
			InfInt cipher = RSA::EncryptOrDecrypt(keyWords[i], targetRSA.GetPublicKey()); // 서버의 공개키로 암호화
			sendPacket << cipher.toString();
		}
		std::cout << '\n';

		client.send(sendPacket);
		break;
	}
	case PacketType::EncryptedMessage: // 클라이언트에서 받은 메시지
	{
		// 키 수신
		std::vector<uint32_t> keyWords(4);
		std::cout << "key: ";
		auto decryptFunc = [&](std::string cipher, int i)
			{
				InfInt plain = RSA::EncryptOrDecrypt(cipher, rsa.GetPrivateKey(), rsa.GetPublicKey()); // 개인키로 복호화
				keyWords[i] = plain.toUnsignedInt();
			};
		std::future<void> futureKey[4];
		for (int i = 0; i < 4; ++i)
		{
			std::string cipher;
			packet >> cipher;
			futureKey[i] = std::async(std::launch::async, decryptFunc, std::move(cipher), i); // 4개 동시에 복호화
		}
		for (int i = 0; i < 4; ++i)
		{
			futureKey[i].get();
			std::cout << keyWords[i] << ' ';
		}
		std::cout << '\n';
		key = Encryptor::WordsToBytes(keyWords);

		break;
	}
	case PacketType::FileTransferReqeust: // 파일을 보내겠다는 신호
	{
		std::cout << "FileTransferReqeust\n";
		packet >> receivedFile;
		if (receivedFile.cipherAlgorithm != -1)
			encryptor.algorithm = static_cast<Encryptor::Algorithm>(receivedFile.cipherAlgorithm);
		receivedFile.bReceived = false;

		receivedFile.data.resize(receivedFile.size);
		bReceiveState = true;

		sendPacket << PacketType::FileTransferRequestACK;
		client.send(sendPacket); // 파일 보내셈
		break;
	}
	case PacketType::FileTransferRequestACK: // 파일을 보내라는 신호
	{
		auto status = client.send(sendFile.data.data(), sendFile.size, sendFile.chunkBytes);
		if (status == sf::Socket::Error)
			std::cout << "Error 5\n";
		bSendState = true;
		break;
	}
	case PacketType::FileReceived: // 상대가 파일을 받았음!
	{
		bClientFileReceving = false;
		break;
	}
	} // switch
}

void Connection::SendingProcess()
{
	sendFile.sendedBytes += sendFile.chunkBytes;
	sendFile.chunkBytes = 0;

	if (sendFile.sendedBytes >= sendFile.size)
	{
		std::cout << "전송 성공: " << sendFile.sendedBytes << "/" << sendFile.size << '\n';
		sendFile.sendedBytes = 0;
		sendFile.bSend = true;
		bSendState = false;
	}
	else if (sendFile.sendedBytes < sendFile.size) // 부분 전송됨
	{
		std::cout << "전송 중: " << sendFile.sendedBytes << "/" << sendFile.size << '\n';
		std::size_t sentSize = 0;
		client.send(sendFile.data.data() + sendFile.sendedBytes, sendFile.size - sendFile.sendedBytes, sendFile.chunkBytes);
	}
}

void Connection::RecevingProcess()
{
	sf::Socket::Status status = client.receive(receivedFile.data.data() + receivedFile.receivedBytes, receivedFile.size - receivedFile.receivedBytes, receivedFile.chunkBytes);
	if (status == sf::Socket::Disconnected)
	{
		std::cout << "연결 끊김\n";
		client.setBlocking(true);
		bConnected = false;
		return;
	}
	if (receivedFile.chunkBytes != 0)
	{
		receivedFile.receivedBytes += receivedFile.chunkBytes;
		std::cout << "받은 바이트: " << receivedFile.receivedBytes << "/" << receivedFile.size << '\n';
		receivedFile.chunkBytes = 0;

		if (receivedFile.receivedBytes >= receivedFile.size)
		{
			// 모든 데이터 수신 완료. 복호화 시작
			std::cout << "파일 복호화\n";
			receivedFile.data = std::move(encryptor.Decrypt(receivedFile.data, key));

			sf::Packet packet;
			packet << FileReceived;
			if (client.send(packet) == sf::Socket::Disconnected)
			{
				std::cout << "연결 끊김\n";
				client.setBlocking(true);
				bConnected = false;
			}

			receivedFile.receivedBytes = 0;
			receivedFile.bReceived = true;
			bReceiveState = false;
		}
	}
}

Connection::Connection(unsigned short port) :
	myIP(sf::IpAddress::getPublicAddress().toString())
{
	if (server.listen(port) != sf::Socket::Status::Done)
	{
		ErrorMessage::Show(u8"해당 포트가 사용중입니다.");
		throw std::runtime_error{ u8"해당 포트가 사용중입니다." };
	}
	server.setBlocking(false);

	if (!rsa.Load("Key"))
	{
		bGeneratingRSA.store(true, std::memory_order_release);
		std::cout << "키 생성 중...\n";
		std::thread thr([&]()
			{
				rsa.CreateRSA();
				rsa.Save("Key");

				if (auto pkiValue = PKI::Load("PKI"); !pkiValue.has_value())
				{
					CreatePKI();
				}
				else
				{
					pki = std::make_unique<PKI>(pkiValue.value());
					bool verify = CA::GetInstance()->Verify(*pki);
					if (verify)
						std::cout << "유효한 인증서\n";
					else
					{
						std::cout << "유효하지 않은 인증서\n";
						CreatePKI();
					}
				}
				bGeneratingRSA.store(false, std::memory_order_release);
			}
		);
		thr.detach();
	}
	else
	{
		if (auto pkiValue = PKI::Load("PKI"); !pkiValue.has_value())
		{
			CreatePKI();
		}
		else
		{
			pki = std::make_unique<PKI>(pkiValue.value());
			bool verify = CA::GetInstance()->Verify(*pki);
			if (verify)
				std::cout << "유효한 인증서\n";
			else
			{
				std::cout << "유효하지 않은 인증서\n";
				CreatePKI();
			}
		}
	}
}

Connection::~Connection()
{
	server.close();
}

void Connection::SetPort(unsigned short port)
{
	server.close();
	if (server.listen(port) != sf::Socket::Status::Done)
	{
		throw std::runtime_error{ u8"해당 포트가 사용중입니다." };
	}
	server.setBlocking(false);
}

bool Connection::Connect(const std::string& ip, unsigned short port)
{
	sf::Socket::Status status = client.connect(ip, port, sf::seconds(3));
	if (status == sf::Socket::Status::Done)
	{
		sf::Packet packet{};
		packet << PacketType::PublicKey << pki->version << pki->ip << pki->pubKey.n.toString() << pki->pubKey.e.toString() << pki->GetSignature().toString();
		if(client.send(packet) == sf::Socket::Status::Done)
		{
			client.setBlocking(false);
			bConnected = true;
			return true;
		}
	}
	return false;
}

void Connection::Update()
{
	if (!bConnected)
	{
		if (server.accept(client) == sf::Socket::Status::Done)
		{
			client.setBlocking(false);
			bConnected = true;
		}
	}
	else
	{
		if (bSendState && sendFile.chunkBytes != 0)
			SendingProcess();
		else if (bReceiveState)
			RecevingProcess();
		else
		{
			sf::Packet packet{};
			auto status = client.receive(packet);

			if (status == sf::Socket::Status::Disconnected)
			{
				std::cout << "연결 끊김\n";
				client.setBlocking(true);
				bConnected = false;
			}
			else if (status == sf::Socket::Status::Done)
			{
				ProcessPacket(packet);
			}
		}
	}
}

bool Connection::IsConnected() const
{
	return bConnected;
}

bool Connection::IsFileReceived() const
{
	return receivedFile.bReceived;
}

bool Connection::IsClientFileReceiving() const
{
	return bClientFileReceving;
}

bool Connection::IsGeneratingRSA() const
{
	return bGeneratingRSA.load(std::memory_order_acquire);
}

bool Connection::SendData(const std::vector<uint8_t>& data, const std::string& name, const Encryptor* encryptor)
{
	bClientFileReceving = true;

	sendFile.name = name;
	sendFile.originalSize = data.size();
	if (encryptor != nullptr)
	{
		sendFile.data = std::move(encryptor->Encrypt(data, key));
		sendFile.cipherAlgorithm = static_cast<int>(encryptor->algorithm);
	}
	else
		sendFile.data = data;
	sendFile.size = sendFile.data.size();
	sendFile.bSend = false;

	sf::Packet packet{};
	packet << PacketType::FileTransferReqeust << sendFile;

	client.send(packet);

	return true;
}

auto Connection::GetRecievedFile() const -> const std::vector<uint8_t>&
{
	return receivedFile.data;
}

auto Connection::GetRecievedFileName() const -> const std::string&
{
	return receivedFile.name;
}

auto Connection::GetRecievedSize() const -> std::size_t
{
	return receivedFile.originalSize;
}
