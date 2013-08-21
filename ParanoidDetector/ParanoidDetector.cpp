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

	// System Call
	mainSystemCall();


	// Routine
	mainRoutine();


	// Shell Code
	mainShellCode();

    PIN_StartProgram();
    return 0;
}