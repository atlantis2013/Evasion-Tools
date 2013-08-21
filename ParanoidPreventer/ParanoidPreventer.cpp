#include "main.h"

namespace WINDOWS
{
	#include<Windows.h>
	#include<Tlhelp32.h>
}

// Anti-Virtualization Preventer

void killSLDT(ADDRINT memoryAddr) {
	 char *d = (char *)memoryAddr;
	 unsigned int* m = (unsigned int *)(d);
	 *m = 0xdead0000;
}

void killSIDT(ADDRINT memoryAddr) {
	 char *d = (char *)memoryAddr;
	 unsigned int* m = (unsigned int *)(d+2);
	 *m = 0xd00dbeef;
}

void killSTR(ADDRINT memoryAddr) {
	 char *d = (char *)memoryAddr;
	 unsigned int* m = (unsigned int *)(d);
	 *m =0xbebaadde;
}

//Modify the magic value
void killEAX() {
	 unsigned int EAX_save;
	 unsigned short int DX_save;
 
	 __asm {
		mov EAX_save, eax
		mov DX_save, dx
	 }
 
	 if ((EAX_save == 0x564D5868) && (DX_save == 0x5658)){
		__asm {
			mov dx, 0x0004
		 }
	}
}

// End of Anti-Virtualization Preventer

// Start of Routine Replacement
VOID killOpenProcess(){
	// just a null function
}

VOID killRegOpenKey(CHAR * name, wchar_t * entry, bool retVal, ADDRINT *addr){
	wstring w = wstring(entry);
	transform(w.begin(), w.end(),w.begin(),towupper);
	
	if(w.find(L"VBOX") != w.npos || w.find(L"VMWARE") != w.npos || w.find(L"VM") != w.npos || w.find(L"ENUM")){
		*addr = 2;
	}
}

VOID Routine(RTN rtn, VOID *v)
{
    string name = RTN_Name(rtn);
    
	if (name == "OpenProcess")
    {
        RTN_Open(rtn);
		RTN_Replace(rtn, (AFUNPTR) killOpenProcess);
        RTN_Close(rtn);
    }

	if (name == "RegOpenKeyExW"){
		RTN_Open(rtn);

		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)killRegOpenKey,
        IARG_ADDRINT, "RegOpenKeyExW",
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCRET_EXITPOINT_VALUE,
		IARG_FUNCRET_EXITPOINT_REFERENCE,
        IARG_END);

		RTN_Close(rtn);
	}
}
// End of Routine Replacement

// Start of ShellCode Instrumentation
void traceInst(INS ins, VOID*)
{
	ADDRINT address = INS_Address(ins);
	
	string ss = INS_Disassemble(ins);
	if(ss.substr(0,4) == "sldt"){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)killSLDT, IARG_MEMORYWRITE_EA, IARG_END);
	}
	else if(ss.substr(0,4) == "sidt"){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)killSIDT, IARG_MEMORYWRITE_EA, IARG_END);
	}
	else if(ss.substr(0,6) == "in eax"){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)killEAX, IARG_END);
	}
	else if(ss.substr(0,3) == "str"){
		//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)killSTR, IARG_END);
	}
}

int main(int argc, char * argv[])
{	 
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)) {
        cerr << "This Pintool returns all the system calls that are executed" << endl;
		cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
		return 0;
    }

	INS_AddInstrumentFunction(traceInst, 0);
	RTN_AddInstrumentFunction(Routine, 0);

    PIN_StartProgram();
    return 0;
}