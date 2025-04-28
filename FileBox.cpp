#include "FileBox.h"

#include <cstdio>
#include <Windows.h>
#include <commdlg.h>
#include <string>
#include <filesystem>
#include <memory>
#include <iostream>

auto FileBox::Open() -> std::optional<FileData>
{
	OPENFILENAME ofn;
	wchar_t szFile[MAX_PATH] = { 0 };

	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = L"모든 파일\0*.*\0텍스트 파일\0*.TXT\0";
	ofn.nFilterIndex = 1;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn))
	{
		FILE* file{ nullptr };
		file = _wfopen(ofn.lpstrFile, L"rb");
		if (file == nullptr)
		{
			DWORD dwError = CommDlgExtendedError();
			if (dwError != 0)
				MessageBox(NULL, L"파일을 여는 데 실패했습니다.", L"오류", MB_ICONERROR);
			return {};
		}

		uint64_t fileSize = std::filesystem::file_size(ofn.lpstrFile);
		std::vector<uint8_t> data(fileSize, 0);
		fread(data.data(), sizeof(uint8_t), fileSize, file);
		
		fclose(file);

        FileData fileData;
        fileData.name = std::filesystem::path{ ofn.lpstrFile }.filename().u8string();
        fileData.wname = ofn.lpstrFile;
        fileData.data = std::move(data);
		return fileData;
	}
	return {};
}

bool FileBox::Save(const std::vector<uint8_t>& data, const std::string& name)
{
    OPENFILENAME ofn;
    wchar_t szFile[MAX_PATH] = { 0 };

    int size = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), name.length(), NULL, 0);
    std::wstring wname(size, 0);
    int converted = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), name.length(), &wname[0], size);

    for (int i = 0; i < wname.size(); ++i)
        szFile[i] = wname[i];

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"모든 파일\0*.*\0텍스트 파일\0*.TXT\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileName(&ofn))
    {
        FILE* file = _wfopen(ofn.lpstrFile, L"wb");
        if (file == nullptr)
        {
            DWORD dwError = CommDlgExtendedError();
            if (dwError != 0)
                MessageBox(NULL, L"파일을 여는 데 실패했습니다.", L"오류", MB_ICONERROR);
            return false;
        }

        size_t written = fwrite(data.data(), sizeof(uint8_t), data.size(), file);
        if (written != data.size())
        {
            MessageBox(NULL, L"파일에 데이터를 쓰는 데 실패했습니다.", L"오류", MB_ICONERROR);
            fclose(file);
            return false;
        }

        fclose(file);
        return true;
    }
    return false;
}
