#include "SignatureScan.h"

void ExternalSignatureScan::initialiseVariables()
{

	this->processName = new char[30];		// to optimize the program we allocate memory on the heap
	this->signature = new char[100];
	this->mask = new char[33];

	system("color 2");

	std::cout << "Process name:" << std::endl;
	std::cout << "Example: process.exe - MAX lenght 30" << std::endl;

	std::cout << std::endl;

	std::cin.getline(processName, 50);

	std::cout << std::endl;

	std::cout << "Signature:" << std::endl;
	std::cout << "Example: \\x12\\x44\\x12\\x00\\x00 - MAX lenght 100" << std::endl;

	std::cout << std::endl;

	std::cin.getline(processName, 50);

	std::cout << std::endl;

	std::cout << "Mask:" << std::endl;
	std::cout << "Example: xxxx??xx??? - MAX lenght 33" << std::endl;

	std::cin.getline(mask, 50);

	std::cout << std::endl;

	std::cout << "Select what do you want to do:" << std::endl;
	std::cout << "<1> Read from memory" << std::endl;
	std::cout << "<2> Write to memory" << std::endl;

	std::cout << std::endl;

	do {
		std::cin >> this->choice;

		if (choice > 2 || choice < 1)
			std::cout << "Error, invalid input" << std::endl;

	}while (choice > 2 || choice < 1);

	if (choice == 2)
	{
		std::cout << "You selected 2, please digit the value:" << std::endl;
		std::cin >> value;
	}
}



bool DataCompare(_In_ const BYTE* data, _In_ const BYTE* mask, _In_ const char* szMask)
{
	for (; *szMask; ++szMask, ++data, ++mask)
	{
	//	std::cout << (short)*data << "|" << (short)*mask << std::endl;


		if (*szMask == 'x' && *data != *mask)
		{
			return false;
		}
	}
	return (*szMask == '\0');
}

bool ExternalSignatureScan::FindPattern()
{
	BYTE* data = new BYTE[this->size];
	SIZE_T bytesread;


	if (!ReadProcessMemory(hProcess, (LPVOID)this->baseAddr, data, this->size, &bytesread))
	{
		std::cerr << "Unable to read memory, Error: " << GetLastError() << std::endl;
		return NULL;
	}

	for (DWORD offset = 0; offset < size; offset++)
	{
		if (DataCompare((CONST BYTE*)(data + offset), (CONST BYTE*) this->signature, this->mask))
		{
			this->baseAddr += offset;
			std::cout << "Pattern found" << std::endl;
			if (this->choice == 1)
			{
				std::cout << "Reading value.." << std::endl;
				ReadProcessMemory(this->hProcess, (LPCVOID)baseAddr, &value, sizeof(value), NULL);
			}
			else {
				std::cout << "Writing value.." << std::endl;
				WriteProcessMemory(this->hProcess, (LPVOID)baseAddr, &value, sizeof(value), NULL);
			}

			delete[] data;
			return 1;
		}
	}
	
	std::cerr << "Unable to find pattern"<<std::endl;
	delete[] data;
	return NULL;
}


HANDLE ExternalSignatureScan::getTargetProcessENTRY()
{
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 Process;
	HANDLE hProcess;
	Process.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,NULL);

	if (Process32First(hSnapshot, &Process))
	{
		do {
			if (!strcmp(Process.szExeFile, this->processName))
			{
				std::cout << "Process found, PID:" << Process.th32ProcessID << std::endl;
				this->PID = Process.th32ProcessID;
				CloseHandle(hSnapshot);
				return hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->PID);
			}

			} while (Process32Next(hSnapshot, &Process));
		}


		std::cerr << "Error: process not found, be sure that program is running" << std::endl;

		CloseHandle(hSnapshot);
		return 0;
}

bool ExternalSignatureScan::getTargetModuleENTRY()
{
	
	MODULEENTRY32 Module;

	Module.dwSize = sizeof(MODULEENTRY32);
	HANDLE _handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->PID);

	if (Module32First(_handle, &Module))
	{
		do {
			if (!strcmp(Module.szModule, this->processName))
			{
				std::cout << "Module informations found" << std::endl;
				std::cout << "Base address is: 0x"<<std::hex << (DWORD)Module.hModule << std::endl;
				this->baseAddr = (DWORD)Module.hModule;
				this->size = (DWORD)Module.modBaseSize;
				return 1;
			}
		} while (Module32Next(_handle, &Module));
	}

	std::cout << "Error, module informations found" << std::endl;
	CloseHandle(_handle);
	return 0;
}

int main()
{
	ExternalSignatureScan scanner;

	system("pause");
}

