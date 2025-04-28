#include "ErrorMessage.h"

#include <Windows.h>
#include <codecvt>
#include <string>

void ErrorMessage::Show(const std::string& msg)
{
	int size = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), msg.length(), NULL, 0);
	std::wstring wstrTo(size, 0);
	int converted = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), msg.length(), &wstrTo[0], size);

	MessageBox(NULL, wstrTo.c_str(), L"오류", MB_ICONERROR);
}
