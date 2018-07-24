#pragma region DEFINES_AND_INCLUDES
#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string.h>
#include <string>

#pragma endregion

class ExternalSignatureScan
{
public: /*Constructors & Destructor*/

	ExternalSignatureScan();
	~ExternalSignatureScan();

public:/*Public methods*/


private: /*Methods*/
	
	void initialiseVariables();
	bool FindPattern();
	HANDLE getTargetProcessENTRY();
	bool getTargetModuleENTRY();

private: /*Members*/

	char * processName;
	char * signature;
	char * mask;

	int value = 0;
	int choice = 0;

	DWORD PID;
	DWORD size;
	DWORD baseAddr;
	HANDLE hProcess;
};


inline ExternalSignatureScan::ExternalSignatureScan()
{
	initialiseVariables();

	hProcess = getTargetProcessENTRY();
	if (getTargetModuleENTRY())
	{

		if (FindPattern() == NULL)
			std::cout << "Cannot find the pattern, error" << std::endl;
		else {
			std::cout << "Pattern found" << std::endl;
		}

	}
}

inline ExternalSignatureScan::~ExternalSignatureScan()
{
	delete[] processName;
	delete[] signature;
	delete[] mask;
}
