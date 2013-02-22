#include "main.h"
#include "SystemCall.h"
#include "AllRoutines.h"

int main(int argc, char * argv[])
{
	  
    PIN_InitSymbols();
	if(PIN_Init(argc, argv)) {
        cerr << "This Pintool returns all the system calls that are executed" << endl;
		cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
		return 0;
    }
	PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
    PIN_AddSyscallExitFunction(&syscall_exit, NULL);
	PIN_AddFiniFunction(SystemFini, 0);
	
	RTN_AddInstrumentFunction(Routine, 0);
	PIN_AddFiniFunction(RoutinesFini, 0);
    
    PIN_StartProgram();
    
    return 0;
}