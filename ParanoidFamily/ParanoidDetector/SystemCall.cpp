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
	//TraceAntiDebug2 << PIN_GetSyscallNumber(ctx,std) << ", " << PIN_GetSyscallArgument(ctx, std, 0) << endl;

	// check for Certain System Call
	if(processdebug ==0 && PIN_GetSyscallNumber(ctx,std) == 154 && PIN_GetSyscallArgument(ctx, std, 1) == 7){
		TraceAntiDebug2 << "debugger, system call, \"ProcessDebugPort\"\n";
		processdebug = 1;
	}

	if(PIN_GetSyscallNumber(ctx,std) == 229 &&  PIN_GetSyscallArgument(ctx, std, 1) == 17){
		TraceAntiDebug2 << "debugger, system call, \"detach debugger\"\n";
	}

	if(PIN_GetSyscallNumber(ctx,std) == 173 && PIN_GetSyscallArgument(ctx, std, 0) == 35){	
		TraceAntiDebug2 << "debugger, system call, \"SystemKernelDebuggerInformation\"\n";
	}
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
   ADDRINT return_value = PIN_GetSyscallReturn(ctx, std);
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