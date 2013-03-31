// GenerateReport.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
using namespace std;

void generateReport(){
	std::ofstream FinalReport;

	FinalReport.open("logs\\report.out");
	string line;
	string antivirtualization = "";
	string antisandbox = "";
	string antidebugging = "";
	
	ifstream antidebugroutines ("logs\\antidebug_routines.out");
	ifstream antidebugshellCode ("logs\\antidebug_shellCode.out");
	ifstream antidebugsystem ("logs\\antidebug_system.out");

	if (antidebugsystem.is_open() && antidebugroutines.is_open() && antidebugshellCode.is_open())
	{
		while ( antidebugsystem.good() )
		{
			getline (antidebugsystem,line);
			antidebugging += line + "\n";
		}
		antidebugsystem.close();

		while ( antidebugroutines.good() )
		{
			getline (antidebugroutines,line);
			antidebugging += line + "\n";
		}
		antidebugroutines.close();

		while ( antidebugshellCode.good() )
		{
			getline (antidebugshellCode,line);
			antidebugging += line + "\n";
		}
		antidebugshellCode.close();
	}


	ifstream antivirtualshellCode ("logs\\antivirtual_shellCode.out");
	ifstream antivirtualsystem ("logs\\antivirtual_system.out");
	ifstream antivirtualroutines ("logs\\antivirtual_routines.out");

	if (antivirtualshellCode.is_open() && antivirtualsystem.is_open() && antivirtualroutines.is_open())
	{
		while ( antivirtualshellCode.good() )
		{
			getline (antivirtualshellCode,line);
			antivirtualization += line + "\n";
		}
		antivirtualshellCode.close();

		while ( antivirtualsystem.good() )
		{
			getline (antivirtualsystem,line);
			antivirtualization += line + "\n";
		}
		antivirtualsystem.close();

		while ( antivirtualroutines.good() )
		{
			getline (antivirtualroutines,line);
			antivirtualization += line + "\n";
		}
		antivirtualroutines.close();
	}

	
	ifstream antisandboxsystem ("logs\\antisandbox_system.out");
	ifstream antisandboxroutines ("logs\\antisandbox_routines.out");
	ifstream antisandboxshellCode ("logs\\antisandbox_shellCode.out");

	if (antisandboxsystem.is_open() && antisandboxroutines.is_open() && antisandboxshellCode.is_open())
	{
		while ( antisandboxsystem.good() )
		{
			getline (antisandboxsystem,line);
			antisandbox += line + "\n";
			
		}
		antisandboxsystem.close();

		while ( antisandboxroutines.good() )
		{
			getline (antisandboxroutines,line);
			antisandbox += line + "\n";
			
		}
		antisandboxroutines.close();

		while ( antisandboxshellCode.good() )
		{
			getline (antisandboxshellCode,line);
			antisandbox += line + "\n";
			
		}
		antisandboxshellCode.close();
	}
	
	std::ofstream TraceAntiDebug;
	std::ofstream TraceAntiVirtual;
	std::ofstream TraceAntiSandbox;

	FinalReport << antivirtualization;
	FinalReport << antisandbox;
	FinalReport << antidebugging;

	TraceAntiDebug.open("logs\\antidebug.out");
	TraceAntiDebug << antidebugging;

	TraceAntiVirtual.open("logs\\antivirtual.out");
	TraceAntiVirtual << antivirtualization;

	TraceAntiSandbox.open("logs\\antisandbox.out");
	TraceAntiSandbox << antisandbox;

	DeleteFile(L"logs\\antidebug_shellCode.out");
	DeleteFile(L"logs\\antisandbox_shellCode.out");
	DeleteFile(L"logs\\antivirtual_shellCode.out");
	DeleteFile(L"logs\\antidebug_system.out");
	DeleteFile(L"logs\\antisandbox_system.out");
	DeleteFile(L"logs\\antivirtual_system.out");
	DeleteFile(L"logs\\antidebug_routines.out");
	DeleteFile(L"logs\\antisandbox_routines.out");
	DeleteFile(L"logs\\antivirtual_routines.out");

}
int _tmain(int argc, _TCHAR* argv[])
{
	generateReport();
	return 0;
}

