#include "AllRoutines.h"

typedef struct RtnName{
    string _name;
    struct RtnName * _next;
}RTNNAME;
// Linked list
RTNNAME *RtnList = 0;

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


// This function is called when the application exits
// It prints the name for each procedure
VOID RoutinesFini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("result.out", ios::app | ios::out);
	
	outFile << "=================== ROUTINE CALL =================" << endl;
		
    for (RTNNAME * rc = RtnList; rc; rc = rc->_next)
    {
		outFile << rc->_name << endl;
    }
	outFile << "=================== END OF ROUTINE CALL =================" << endl;
    
}

/*int main(int argc, char * argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

    outFile.open("result.out");

    // Initialize pin
    if (PIN_Init(argc, argv)) {
		cerr << "This Pintool returns all the routines that are executed" << endl;
		cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
		return;
	}

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}*/