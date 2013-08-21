#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <set>
#include <list>
#include <sstream>
#include "test.h"

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

bool isSeDebugCheck = 0;

VOID PrintArguments(CHAR * name, ADDRINT arg0, ADDRINT arg1)
{
    TraceFile << name << "(" << arg0 << ", " << arg1<< ")" << endl;
}


VOID PrintArguments_Process(CHAR * name, ADDRINT arg0)
{
	if(WINDOWS::getProcessID("csrss.exe") == arg0 && isSeDebugCheck == 0){
		TraceFile << "Anti-Debug: Executable enables SeDebugPrivilege." << endl;
		isSeDebugCheck = 1;
	}
}
VOID Image(IMG img, VOID *v)
{
    RTN cfwRtn = RTN_FindByName(img, "RegOpenKeyExW");
    if (RTN_Valid(cfwRtn))
    {
        RTN_Open(cfwRtn);

        RTN_InsertCall(cfwRtn, IPOINT_BEFORE, (AFUNPTR)PrintArguments,
        IARG_ADDRINT, "RegOpenKeyExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
		IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_END);
        RTN_Close(cfwRtn);
    }

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
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << endl;
    
    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  mainTest()
{
  
    TraceFile.open("call.out");

    TraceFile << hex;
    TraceFile.setf(ios::showbase);
   
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

	return 1;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
