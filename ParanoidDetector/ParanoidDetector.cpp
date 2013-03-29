#include "main.h"
#include "SystemCall.h"
#include "AllRoutines.h"
#include "ShellCode.h"
#include "test.h"

int main(int argc, char * argv[])
{
	  
    PIN_InitSymbols();
	if(PIN_Init(argc, argv)) {
        cerr << "This Pintool returns all the system calls that are executed" << endl;
		cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
		return 0;
    }
	setTraceFile("logs\\systemCall.out");
	PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
    PIN_AddSyscallExitFunction(&syscall_exit, NULL);
	
	mainShellCode();
	mainRoutine();
    
	
    PIN_StartProgram();
    
    return 0;
}