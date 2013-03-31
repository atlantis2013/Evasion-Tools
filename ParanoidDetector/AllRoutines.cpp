#include "AllRoutines.h"
#include <algorithm>
typedef struct RtnName{
    string _name;
    struct RtnName * _next;
}RTNNAME;
// Linked list
RTNNAME *RtnList = 0;
namespace WINDOWS
{
#include <stdio.h>
	#include <iostream>
	#include <fstream>
	#include <iomanip>
	#include <set>
	#include <list>
	#include <sstream>
	#include <tchar.h>
	#include <Windows.h>
	#include <conio.h>
	#include <excpt.h>
	#include <Psapi.h>
	#include <algorithm>
	#include <string>
	#include <tlhelp32.h>
	#include <windows.h>
	#include <stdio.h>
	#include <wchar.h>
	#include <string.h>

	int getProcessID(string procName){
		  HANDLE hProcessSnap;

		  PROCESSENTRY32 pe32;

		  // Take a snapshot of all processes in the system.
		  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		  if( hProcessSnap == INVALID_HANDLE_VALUE )
		  {
			return( -1 );
		  }

		  // Set the size of the structure before using it.
		  pe32.dwSize = sizeof( PROCESSENTRY32 );

		  // Retrieve information about the first process,
		  // and exit if unsuccessful
		  if( !Process32First( hProcessSnap, &pe32 ) )
		  {
			CloseHandle( hProcessSnap );          // clean the snapshot object
			return( -1 );
		  }

		  // Now walk the snapshot of processes, and
		  // display information about each process in turn
		  do
		  {
			 if(pe32.szExeFile == procName){
				 return pe32.th32ProcessID;
			 }
		  } while( Process32Next( hProcessSnap, &pe32 ) );

		  CloseHandle( hProcessSnap );
		  return( -1 );
	}
}
std::ofstream TraceFile;
std::ofstream TraceAntiDebug;
std::ofstream TraceAntiVirtual;
std::ofstream TraceAntiSandbox;
std::wofstream TraceRegistry;

bool switchDesktop = 0;
bool setThreadDesktop = 0;
bool isdebuggerpresent = 0;
bool checkremote = 0;
bool SetUnhandledExceptionFilter = 0;
bool blockInput = 0;

const char * StripPath(const char * path)
{
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
}

VOID Routine(RTN rtn, VOID *v)
{
    RTNNAME *rc = new RTNNAME;
    rc->_name = RTN_Name(rtn);
    // Add to list of routines
    rc->_next = RtnList;
    RtnList = rc;
}

bool isSeDebugCheck = 0;
bool virtualdisk = 0;
bool vm = 0;
bool vbox = 0;
bool windowsProduct = 0;

VOID PrintArguments_RegOpenKey(CHAR * name, ADDRINT arg0, wchar_t * arg1)
{
    wstring w = wstring(arg1);
	transform(w.begin(), w.end(),w.begin(),towupper);
	//wcout << w << "\n";
	//TraceRegistry.write((char*)arg1, wcslen(arg1) * sizeof(wchar_t));
	TraceRegistry << arg1 << "\n";
	if(w.find(L"VBOX") != w.npos && vbox == 0){
		//TraceFile << "Anti-VirtualBox: Checking for Vbox environment" << "\n";
		TraceAntiVirtual << "Anti-VirtualBox:		Checking for Vbox environment" << "\n";
		vbox = 1;
	}

	if(w.find(L"VIRTUALBOX") != w.npos && vbox == 0){
		//TraceFile << "Anti-VirtualBox: Checking for Vbox environment" << "\n";
		TraceAntiVirtual << "Anti-VirtualBox:		Checking for Vbox environment" << "\n";
		vbox = 1;
	}

	if( w.find(L"VMWARE") != w.npos || w.find(L"VMTOOLS") != w.npos || w.find(L"VM") != w.npos){
		if(vm==0){
			//TraceFile << "Anti-VM: Checking for vm environment (VMWare, VMTools in registry)" << "\n";
			TraceAntiVirtual << "Anti-VMWare:		Checking for vm environment (VMWare, VMTools in registry)" << "\n";
			vm = 1;
		}
	}


}

VOID PrintArguments_RegQueryKey(CHAR * name, ADDRINT arg0, wchar_t * arg1)
{
    wstring w = L" " + wstring(arg1) + L" " ;
	transform(w.begin(), w.end(),w.begin(),towupper);
	//TraceRegistry.write((char*)arg1, wcslen(arg1) * sizeof(wchar_t));
	TraceRegistry << arg1 << "\n";
	//wcout << w << "\n";
	if(w.find(L" 0 ") != w.npos || w.find(L" IDENTIFIER ")!= w.npos){
		if(virtualdisk == 0){
			//TraceFile << "Anti-Virtualization: Checking on virtual disk.\n";
			TraceAntiVirtual << "Anti-Virtualization:	Checking on virtual disk.\n";
			virtualdisk =1 ;
		}
	}

	if(w.find(L" PRODUCTID ") != w.npos && windowsProduct == 0){
		//TraceFile << "Anti-Sandbox: Checking on Windows Operating system's product ID\n";
		TraceAntiSandbox << "Anti-Sandbox:		Checking on Windows Operating system's product ID\n";
		windowsProduct = 1;
	}
}


VOID PrintArguments_Process(CHAR * name, ADDRINT arg0)
{
	if(WINDOWS::getProcessID("csrss.exe") == arg0 && isSeDebugCheck == 0){
		//TraceFile << "Anti-Debugging: Executable enables SeDebugPrivilege." << endl;
		TraceAntiDebug << "Anti-Debugging:		Executable enables SeDebugPrivilege." << endl;
		isSeDebugCheck = 1;
	}
}

VOID PrintArguments_FindWindow(CHAR * name, wchar_t * arg0)
{
	 wstring w = wstring(arg0);
	 transform(w.begin(), w.end(),w.begin(),towupper);
	 wcout << w << "\n";
	TraceFile << w.c_str() << "\n";
}
VOID Image(IMG img, VOID *v)
{
	RTN cfwRtn = RTN_FindByName(img, "RegOpenKeyExW");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_RegOpenKey,
        IARG_ADDRINT, "RegOpenKeyExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_END);
        RTN_Close(cfwRtn);
    }
	

    cfwRtn = RTN_FindByName(img, "RegQueryValueExW");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_RegQueryKey,
        IARG_ADDRINT, "RegQueryValueExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_END);
        RTN_Close(cfwRtn);
    }

	
	/*
	cfwRtn = RTN_FindByName(img, "FindWindow");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_FindWindow,
        IARG_ADDRINT, "FindWindow",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);
        RTN_Close(cfwRtn);
    }*/

	/* checks for SeDebug*/
	cfwRtn = RTN_FindByName(img, "OpenProcess");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_Process,
        IARG_ADDRINT, "OpenProcess",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_END);
        RTN_Close(cfwRtn);
    }
}

// This function is called when the application exits
// It prints the name for each procedure
VOID RoutinesFini(INT32 code, VOID *v)
{
	ofstream outFile, outFile2;
	//outFile2.open("logs\\allFunctions.out", ios::app|ios::out);
		
    for (RTNNAME * rc = RtnList; rc; rc = rc->_next)
    {
		//outFile2 << rc->_name << endl;
		
		if(rc->_name == "IsDebuggerPresent" && isdebuggerpresent == 0){
			//TraceFile << "Anti-Debugging: Executable attempts to check for debugger via isDebuggerPresent " << endl;
			TraceAntiDebug<< "Anti-Debugging:	Executable attempts to check for debugger via isDebuggerPresent " << endl;
			isdebuggerpresent = 1;
		}

		if(rc->_name == "CheckRemoteDebuggerPresent" && checkremote == 0){
			//TraceFile << "Anti-Debugging: Executable attempts to check for debugger via CheckRemoteDebuggerPresent " << endl;
			TraceAntiDebug << "Anti_DeAnti-Debugging:		Executable attempts to check for debugger via CheckRemoteDebuggerPresent " << endl;
			checkremote = 1;
		}

		if(rc->_name == "SetUnhandledExceptionFilter" && SetUnhandledExceptionFilter == 0){
			//TraceFile << "Anti-Debugging: Executable attempts to check for debugger via SetUnhandledExceptionFilter " << endl;
			TraceAntiDebug<< "Anti-Debugging:		Executable attempts to check for debugger via SetUnhandledExceptionFilter " << endl;
			SetUnhandledExceptionFilter = 1;
		}

		if(rc->_name == "BlockInput" && blockInput == 0){
			//TraceFile << "Anti-Debugging: Executable attempts block input." << endl;
			TraceAntiDebug<< "Anti-Debugging:		Executable attempts block input." << endl;
			blockInput = 1;
		}
		if(rc->_name == "SwitchDesktop"){
			switchDesktop = 1;
		}

		if(rc->_name == "SetThreadDesktop"){
			setThreadDesktop = 1;
		}

		if(switchDesktop == 1 && setThreadDesktop == 1){
			//TraceFile << "Anti-Debugging: Executable attempts to switch desktop.\n";
			TraceAntiDebug << "Anti-Debugging:		Executable attempts to switch desktop.\n";
			switchDesktop = 0;
			setThreadDesktop = 0;
		}
    }
    
}
VOID Fini(INT32 code, VOID *v)
{
    
    TraceFile.close();
}

int mainRoutine()
{
	TraceAntiDebug.open("logs\\routines.out");
	TraceAntiVirtual.open("logs\\routines.out");
	TraceAntiSandbox.open("logs\\routines.out");
	TraceRegistry.open("logs\\registry.out");
	//TraceFile.open("logs\\functions.out");
    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(RoutinesFini, 0);
	IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    return 0;
}