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
	#include <strsafe.h>
	#include <psapi.h>

	#define BUFSIZE 512

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

	BOOL GetFileNameFromHandle(HANDLE hFile) 
	{
	  BOOL bSuccess = FALSE;
	  TCHAR pszFilename[MAX_PATH+1];
	  HANDLE hFileMap;

	  // Get the file size.
	  DWORD dwFileSizeHi = 0;
	  DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 

	  if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
	  {
		 _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
		 return FALSE;
	  }

	  // Create a file mapping object.
	  hFileMap = CreateFileMapping(hFile, 
						NULL, 
						PAGE_READONLY,
						0, 
						1,
						NULL);

	  if (hFileMap) 
	  {
		// Create a file mapping to get the file name.
		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

		if (pMem) 
		{
		  if (GetMappedFileName (GetCurrentProcess(), 
								 pMem, 
								 pszFilename,
								 MAX_PATH)) 
		  {

			// Translate path with device name to drive letters.
			TCHAR szTemp[BUFSIZE];
			szTemp[0] = '\0';

			if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) 
			{
			  TCHAR szName[MAX_PATH];
			  TCHAR szDrive[3] = TEXT(" :");
			  BOOL bFound = FALSE;
			  TCHAR* p = szTemp;

			  do 
			  {
				// Copy the drive letter to the template string
				*szDrive = *p;

				// Look up each device name
				if (QueryDosDevice(szDrive, szName, MAX_PATH))
				{
				  size_t uNameLen = _tcslen(szName);

				  if (uNameLen < MAX_PATH) 
				  {
					bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
							 && *(pszFilename + uNameLen) == _T('\\');

					if (bFound) 
					{
					  // Reconstruct pszFilename using szTempFile
					  // Replace device path with DOS path
					  TCHAR szTempFile[MAX_PATH];
					  StringCchPrintf(szTempFile,
								MAX_PATH,
								TEXT("%s%s"),
								szDrive,
								pszFilename+uNameLen);
					  StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
					}
				  }
				}

				// Go to the next NULL character.
				while (*p++);
			  } while (!bFound && *p); // end of string
			}
		  }
		  bSuccess = TRUE;
		  UnmapViewOfFile(pMem);
		} 

		CloseHandle(hFileMap);
	  }
	  _tprintf(TEXT("File name is %s\n"), pszFilename);
	  return(bSuccess);
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
bool vmwaretray = 0;
bool vmtoolsd = 0;
bool vmacthlp = 0;

const char * StripPath(const char * path)
{
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
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

	//TraceRegistry << arg1 << "\n";
	if(w.find(L"VBOX") != w.npos && vbox == 0){
		//TraceFile << "Anti-VirtualBox: Checking for Vbox environment" << "\n";
		TraceAntiVirtual << "virtualbox,registry,\"vbox\"" << endl;
		vbox = 1;
	}

	if(w.find(L"VIRTUALBOX") != w.npos && vbox == 0){
		//TraceFile << "Anti-VirtualBox: Checking for Vbox environment" << "\n";
		TraceAntiVirtual << "virtualbox, registry, \"virtualbox\"" << "\n";
		vbox = 1;
	}

	if( w.find(L"VMWARE") != w.npos || w.find(L"VMTOOLS") != w.npos || w.find(L"VM") != w.npos){
		if(vm==0){
			//TraceFile << "Anti-VM: Checking for vm environment (VMWare, VMTools in registry)" << "\n";
			TraceAntiVirtual << "vmware, registry, \"vm\"" << "\n";
			vm = 1;
		}
	}

	if( w.find(L"VideoBios") != w.npos){
		TraceAntiVirtual << "vmware, registry, \"videobios\"" << "\n";
	}

}

VOID PrintArguments_RegQueryKey(CHAR * name, ADDRINT arg0, wchar_t * arg1)
{
    wstring w = L" " + wstring(arg1) + L" " ;
	transform(w.begin(), w.end(),w.begin(),towupper);
	
	if(w.find(L" 0 ") != w.npos || w.find(L" IDENTIFIER ")!= w.npos){
		if(virtualdisk == 0){
			//TraceFile << "Anti-Virtualization: Checking on virtual disk.\n";
			TraceAntiVirtual << "vmware, registry, \"0\", \"identifier\"\n";
			virtualdisk =1 ;
		}
	}

	if(w.find(L" PRODUCTID ") != w.npos && windowsProduct == 0){
		//TraceFile << "Anti-Sandbox: Checking on Windows Operating system's product ID\n";
		TraceAntiSandbox << "sandbox, registry, \"productid\"\n";
		windowsProduct = 1;
	}

	if( w.find(L"VideoBios") != w.npos){
		TraceAntiVirtual << "vmware, registry, \"videobios\"" << "\n";
	}

}

VOID PrintArguments_Process(CHAR * name, ADDRINT arg0)
{
	if(WINDOWS::getProcessID("csrss.exe") == arg0 && isSeDebugCheck == 0){
		//TraceFile << "Anti-Debugging: Executable enables SeDebugPrivilege." << endl;
		TraceAntiDebug << "debugger, process, \"csrss.exe\", \"SeDebugPrivileges\"\n";
		isSeDebugCheck = 1;
	}

	if(WINDOWS::getProcessID("vmacthlp.exe") == arg0 && vmacthlp == 0){
		TraceAntiVirtual << "vmware, process, \"vmacthlp.exe\"\n";
		vmacthlp = 1;
	}

	if(WINDOWS::getProcessID("vmtoolsd.exe") == arg0 && vmtoolsd == 0){
		TraceAntiVirtual << "vmware, process, \"vmtoolsd.exe\"\n";
		vmtoolsd = 1;
	}

	if(WINDOWS::getProcessID("VMwareTray.exe") == arg0 && vmwaretray == 0){
		TraceAntiVirtual << "vmware, process, \"vmwaretray.exe\"\n";
		vmwaretray = 1;
	}
}

VOID PrintArguments_FindWindow(CHAR * name, wchar_t * arg0)
{
	 wstring w = wstring(arg0);
	 transform(w.begin(), w.end(),w.begin(),towupper);
	 wcout << w << "\n";
	TraceFile << w.c_str() << "\n";
}

VOID checkIsDebuggerPresent(CHAR * name, bool retVal){
	TraceAntiDebug << "debugger, api, \"isDebuggerPresent\"\n";
	isdebuggerpresent = 1;
}

VOID checkIsRemoteDebuggerPresent(CHAR *name, bool retVal){
	TraceAntiDebug << "debugger, api, \"CheckremoteDebuggerPresent\"\n";
	checkremote = 1;
}

VOID checkGetFileAttributes(CHAR * name, ADDRINT arg0){
	//TraceAntiDebug << name << endl;
}

VOID PrintArguments_OpenFile(CHAR * name, ADDRINT arg0, ADDRINT arg1){
	//printf("FILEHANDLE: %x, %x\n", arg0,arg1);
	//WINDOWS::GetFileNameFromHandle((WINDOWS::HANDLE) arg0);
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

	cfwRtn = RTN_FindByName(img, "GetFileAttributesA");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)checkGetFileAttributes,
        IARG_ADDRINT, "GetFileAttributesA",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
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
}
VOID Fini(INT32 code, VOID *v)
{
    TraceFile.close();
}


VOID Routine(RTN rtn, VOID *v)
{
    RTNNAME *rc = new RTNNAME;
    rc->_name = RTN_Name(rtn);
 
	if(rc->_name == "RegOpenKeyExW"){
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_RegOpenKey,
        IARG_ADDRINT, "RegOpenKeyExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_END);
        RTN_Close(rtn);
	}
	if(rc->_name == "RegQueryValueExW")
    {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_RegQueryKey,
        IARG_ADDRINT, "RegQueryValueExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_END);
        RTN_Close(rtn);
    }

	/* checks for SeDebug*/
	if (rc->_name == "OpenProcess")
    {
        RTN_Open(rtn);

        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments_Process,
        IARG_ADDRINT, "OpenProcess",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_END);
        RTN_Close(rtn);
    }

	// Checks for Debugger
	if(rc->_name == "IsDebuggerPresent" && isdebuggerpresent == 0){
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)checkIsDebuggerPresent,
        IARG_ADDRINT, "IsDebuggerPresent",
        IARG_FUNCRET_EXITPOINT_VALUE,
        IARG_END);

		RTN_Close(rtn);
	}

	if(rc->_name == "CheckRemoteDebuggerPresent" && checkremote == 0){
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)checkIsRemoteDebuggerPresent,
        IARG_ADDRINT, "CheckRemoteDebuggerPresent",
        IARG_FUNCRET_EXITPOINT_VALUE,
        IARG_END);

		RTN_Close(rtn);
	}

	if(rc->_name == "SetUnhandledExceptionFilter" && SetUnhandledExceptionFilter == 0){
		//TraceAntiDebug << "debugger, api, \"SetUnhandledExceptionFilter\"\n";
		SetUnhandledExceptionFilter = 1;
	}

	if(rc->_name == "BlockInput" && blockInput == 0){
		//TraceAntiDebug << "debugger, api, \"blockInput\"\n";
		blockInput = 1;
	}
}

int mainRoutine()
{
	TraceAntiDebug.open("logs\\antidebug_routines.out");
	TraceAntiVirtual.open("logs\\antivirtual_routines.out");
	TraceAntiSandbox.open("logs\\antisandbox_routines.out");
	TraceRegistry.open("logs\\registry.out");
	RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(RoutinesFini, 0);
	IMG_AddInstrumentFunction(Image, (VOID *) 1);
    PIN_AddFiniFunction(Fini, 0);
    
    return 0;
}