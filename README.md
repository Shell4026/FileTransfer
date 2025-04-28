# 종단간 암호화 파일 전송 프로그램
취지: 종단간 통신을 이용하여 제3자가 감청 할 수 없게 파일을 암호화 해서 양측에서 전송하고 받자.

## 영상
https://github.com/user-attachments/assets/311463a9-0dc6-439d-b345-f27562a86dad

[보내는 시점]

https://github.com/user-attachments/assets/f7d17b89-68dc-4b21-b32d-882e8e305572

[받는 시점]

## 간단 원리
1. 각자의 컴퓨터에서 RSA로 개인키와 공개키 생성
2. 각 컴퓨터에서 가상의 CA의 서명을 통해 인증서를 생성 (중간자 공격 방지)
3. PC1이 PC2에 연결을 할 때 인증서를 보내고, PC2는 CA의 공개키를 통해 인증서를 검증 (검증이 됐다면 PC2도 PC1에 인증서를 보낸다.)
4. PC1은 랜덤하게 128비트 키를 생성 -> 해당 키를 PC2의 인증서에 있던 공개키로 암호화 후 전송 (암호화 키 공유 성공)
5. 이제 서로 키를 가지고 있기 때문에 파일을 대칭키를 이용해 암호화 후 전송

## 상세 원리

### 소수 생성 방식
밀러 라빈 소수 판별법을 이용해 O(klog^3 n) (k: 샘플 소수의 개수, n: 판별할 수의 길이) 시간 안에 확률적으로 소수를 판별 할 수 있다.
### RSA 키 생성 과정
1. 랜덤한 512비트의 수를 두 개 생성 (두 수를 곱하면 1024비트기에)
2. 짝수라면 1을 더하고 밀러-라빈 소수 판별법을 이용해 소수인지 판별한다.</br>
2-1. 소수가 아니라면 1을 더한 후 반복 
3. 두 소수를 이용해 키 생성
   
이 때 소수는 멀티 스레드를 이용해 최대한 빨리 계산한다. 

### 암호문 패딩
PCKS7 패딩</br>
암호문이 블록 크기와 맞지 않으면 해당 패딩을 통해 채움</br>
빈 블록 공간 만큼 그 공간의 크기의 숫자로 채우는 직관적인 방식</br>

### 패킷 처리
Connection 클래스에서 받은 패킷의 종류에 따라 처리한다.

보내는 패킷은 패킷 타입을 우선으로 보내고 뒤에 필요한 정보를 붙여서 보낸다.
```c++
void Connection::ProcessPacket(sf::Packet& packet)
{
	int type;
	packet >> type;

	sf::Packet sendPacket;
	switch (type)
	{
	case PacketType::PublicKey: // 클라이언트에게서 공개키를 받았음
	{
		/*...*/
		sendPacket << PacketType::PublicKeyACK << pki->version << pki->ip << pki->pubKey.n.toString() << pki->pubKey.e.toString() << pki->GetSignature().toString();
		client.send(sendPacket);
		break;
	}
	case PacketType::PublicKeyACK: // 서버에게서 공개키를 받았음, 서로 공개키 교환 완료
	{
		/*...*/
		break;
	}
	case PacketType::EncryptedMessage: // 클라이언트에서 받은 메시지
	{
		/*...*/
		break;
	}
	case PacketType::FileTransferReqeust: // 파일을 보내겠다는 신호
	{
		/*...*/
		break;
	}
	case PacketType::FileTransferRequestACK: // 파일을 보내라는 신호
	{
		/*...*/
		break;
	}
	case PacketType::FileReceived: // 상대가 파일을 받았음!
	{
		/*...*/
		break;
	}
	} // switch
```
## 종속성
[SFML](https://github.com/SFML/SFML)

[imgui](https://github.com/ocornut/imgui)
