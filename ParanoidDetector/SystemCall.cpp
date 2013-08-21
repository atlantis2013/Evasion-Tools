/*
    Author:     Lim Seok Min
    Email:      a0073541@nus.edu.sg
    Purpose:    This tool will return all the routines called by the program.

    Reference:  http://jbremer.org/malware-unpacking-level-pintool/#rp-syscall
*/

#include "SystemCall.h"
//ofstream traceFile2("logs\\system.out");
//ofstream traceFileAll("logs\\allSystem.out");
std::ofstream TraceAntiDebug2("logs\\antidebug_system.out");
std::ofstream TraceAntiVirtual2("logs\\antivirtual_system.out");
std::ofstream TraceAntiSandbox2("logs\\antisandbox_system.out");

void setTraceFile(string file){
	//traceFile2.open(file);
}
bool processdebug = 0;

void syscall_entry(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
	TraceAntiDebug2 << PIN_GetSyscallNumber(ctx,std) << ", " << PIN_GetSyscallArgument(ctx, std, 0) << endl;

	// check for Certain System Call
	if(processdebug ==0 && PIN_GetSyscallNumber(ctx,std) == 154 && PIN_GetSyscallArgument(ctx, std, 1) == 7){
		//traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " at 7 -> Anti-Debugging: Executable is checking for ProcessDebugPort\n";
		TraceAntiDebug2 << "Anti-Debugging:		System Call 154 called. Argument 1 = 7. Executable is checking for ProcessDebugPort\n";
		processdebug = 1;
	}

	if(PIN_GetSyscallNumber(ctx,std) == 229 &&  PIN_GetSyscallArgument(ctx, std, 1) == 17){
		//traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " at 0x11 -> Anti-Debugging: Executable attempts to detach debugger.\n";
		TraceAntiDebug2 << "Anti-Debugging:		System Call 229 called. Argument 1 = 17. Executable attempts to detach debugger.\n";
	}

	if(PIN_GetSyscallNumber(ctx,std) == 173 && PIN_GetSyscallArgument(ctx, std, 0) == 35){
		//traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " 0x35 -> Anti-Debugging: Executable is checking for SystemKernelDebuggerInformation\n";
		TraceAntiDebug2 << "Anti-Debugging:		System call 173 called. Argument 0 = 35. Executable is checking for SystemKernelDebuggerInformation\n";
	}
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
   ADDRINT return_value = PIN_GetSyscallReturn(ctx, std);
   // printf(", return-value: %d 0x%08x\n", return_value,
    //    return_value);

}

void SystemCallfini(INT32, VOID*)
{
   // traceFile2.close();
}


int mainSystemCall()
{
	setTraceFile("logs\\systemCall.out");
	PIN_AddSyscallEntryFunction(&syscall_entry, NULL);
    PIN_AddSyscallExitFunction(&syscall_exit, NULL);
    return 0;
}