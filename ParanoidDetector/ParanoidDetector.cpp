#include "main.h"
#include "SystemCall.h"
#include "AllRoutines.h"
#include "ShellCode.h"

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

	RTN_AddInstrumentFunction(Routine, 0);
	PIN_AddFiniFunction(RoutinesFini, 0);
    
        
    //TRACE_AddInstrumentFunction(Trace, 0);
   // PIN_AddFiniFunction(TraceFini, 0);
	
    PIN_StartProgram();
    
    return 0;
}