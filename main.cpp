#include "Connection.h"
#include "FileBox.h"
#include "Encryptor.h"
#include "AES.h"
#include "ErrorMessage.h"

#include <SFML/Window.hpp>
#include <SFML/Graphics.hpp>

#include <imgui.h>
#include <imgui-SFML.h>
#include <misc/cpp/imgui_stdlib.h>

#include <iostream>
#include <vector>

constexpr uint32_t WIDTH = 400;
constexpr uint32_t HEIGHT = 300;

Connection connection{ 4026 };
FileBox fb{};
Encryptor encryptor{};

std::vector<uint8_t> fileData;
std::string fileName;

const char* items[] = { "XXTEA", "AES" };

void RenderUI()
{
	ImGui::SetNextWindowPos(ImVec2{ 0, 0 }, ImGuiCond_::ImGuiCond_Always);
	ImGui::SetNextWindowSize(ImVec2{ WIDTH, HEIGHT }, ImGuiCond_::ImGuiCond_Always);
	
	static ImGuiWindowFlags flag = ImGuiWindowFlags_::ImGuiWindowFlags_NoMove | ImGuiWindowFlags_::ImGuiWindowFlags_NoDecoration;
	ImGui::Begin("Connect", nullptr, flag);
	if (connection.IsGeneratingRSA())
	{
		const char* waitStr = "Generating RSA key... Please wait a moment.";
		float textWidth = ImGui::CalcTextSize(waitStr).x;
		float windowWidth = ImGui::GetWindowWidth();
		ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
		ImGui::Text(waitStr);
	}
	else
	{
		// 타이틀
		{
			float textWidth = ImGui::CalcTextSize("Encrypted File Transfer").x;
			float windowWidth = ImGui::GetWindowWidth();
			ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 0, 255));
			ImGui::Text("Encrypted File Transfer");
			ImGui::PopStyleColor();
			ImGui::Separator();
		}
		ImGui::Text("My IP: %s", connection.myIP.c_str());
		static int myPort = 4026;
		ImGui::Text("My Port: ");
		ImGui::SameLine();
		ImGui::SetNextItemWidth(50);
		ImGui::InputInt("##MyPort", &myPort, 0, 0);
		ImGui::SameLine();
		if (ImGui::Button("Change"))
		{
			std::cout << "포트 변경: " << myPort << '\n';
			connection.SetPort(myPort);
		}
		ImGui::Separator();

		static std::string ip{};
		ImGui::Text("IP/Port");
		ImGui::SameLine();
		ImGui::SetNextItemWidth(100);
		ImGui::InputText("##ip", &ip);
		ImGui::SameLine();
		static int targetPort = 4026;
		ImGui::SetNextItemWidth(50);
		ImGui::InputInt("##port", &targetPort, 0, 0);
		if (ImGui::Button("Connect"))
			connection.Connect(ip, targetPort);
		if (connection.IsConnected())
		{
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 0, 255));
			ImGui::Text("Connected");
			ImGui::PopStyleColor();
		}
		else
		{
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
			ImGui::Text("Disconnected");
			ImGui::PopStyleColor();
		}
		if (connection.IsFileReceived())
		{
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 255, 0, 255));
			ImGui::Text("File received: ");
			ImGui::PopStyleColor();
			ImGui::SameLine();
			ImGui::Text("%d bytes", connection.GetRecievedSize());
			if (ImGui::Button("Download"))
			{
				fb.Save(connection.GetRecievedFile(), connection.GetRecievedFileName());
			}
		}
		else
		{
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
			ImGui::Text("File not received: ");
			ImGui::PopStyleColor();
			ImGui::SameLine();
			ImGui::Text("%d bytes", connection.GetRecievedSize());
		}

		ImGui::Combo("Algorithm", reinterpret_cast<int*>(&encryptor.algorithm), items, 2);

		if (fileData.empty())
		{
			float y = HEIGHT - 25;
			ImGui::SetCursorPosY(y);
			if (ImGui::Button("Select file", ImVec2(WIDTH, 0)))
			{
				auto data = fb.Open();
				if (data.has_value())
				{
					fileData = std::move(data->data);
					fileName = std::move(data->name);
				}
			}
		}
		else
		{
			float y = HEIGHT - 65;
			ImGui::SetCursorPosY(y);
			ImGui::Text("File size: %d bytes", fileData.size());
			if (!connection.IsClientFileReceiving())
			{
				if (ImGui::Button("Send file", ImVec2(WIDTH, 0)))
				{
					if (!fileData.empty())
						connection.SendData(fileData, fileName, &encryptor);
				}
			}
			else
			{
				ImGui::Button("Sending...", ImVec2(WIDTH, 0));
			}
			if (ImGui::Button("Select file", ImVec2(WIDTH, 0)))
			{
				auto data = fb.Open();
				if (data.has_value())
				{
					fileData = std::move(data->data);
					fileName = std::move(data->name);
				}
			}
		}
	}

	ImGui::End();
}

int main()
{
	try
	{
		sf::RenderWindow win{ sf::VideoMode{WIDTH, HEIGHT}, L"파일 전송기", sf::Style::Close };
		sf::Event e{};

		win.setFramerateLimit(60);
		ImGui::SFML::Init(win);

		sf::Clock deltaClock{};
		while (win.isOpen())
		{
			while (win.pollEvent(e))
			{
				ImGui::SFML::ProcessEvent(e);
				switch (e.type)
				{
				case sf::Event::Closed:
					win.close();
					break;
				}
			}

			ImGui::SFML::Update(win, deltaClock.restart());
			win.clear();

			RenderUI();

			ImGui::SFML::Render(win);
			win.display();

			connection.Update();
		}
	}
	catch (const std::runtime_error& e)
	{
		ErrorMessage::Show(e.what());
	}
	catch (const std::invalid_argument& e)
	{
		ErrorMessage::Show(e.what());
	}
	return 0;
}