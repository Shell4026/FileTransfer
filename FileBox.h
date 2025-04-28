#pragma once

#include <optional>
#include <vector>
#include <cstdint>
#include <utility>
#include <string>

class FileBox
{
public:
	struct FileData
	{
		std::string name;
		std::wstring wname;
		std::vector<uint8_t> data;
	};
public:
	auto Open() -> std::optional<FileData>;
	bool Save(const std::vector<uint8_t>& data, const std::string& name);
};

