/*
    Author:     Lim Seok Min
    Email:      a0073541@nus.edu.sg
    Purpose:    This tool will return all the routines called by the program.

    Reference:  http://jbremer.org/malware-unpacking-level-pintool/#rp-syscall
*/

#include "SystemCall.h"
ofstream traceFile2("logs\\system.out");
ofstream traceFileAll("logs\\allSystem.out");

void setTraceFile(string file){
	//traceFile2.open(file);
}

void syscall_entry(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
	// check for Certain System Call
	if(PIN_GetSyscallNumber(ctx,std) == 154 && PIN_GetSyscallArgument(ctx, std, 1) == 7){
		traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " at 7 -> Anti-Debugging: Executable is checking for ProcessDebugPort\n";
	}

	if(PIN_GetSyscallNumber(ctx,std) == 229 &&  PIN_GetSyscallArgument(ctx, std, 1) == 17){
		traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " at 0x11 -> Anti-Debugging: Executable attempts to detach debugger.\n";
	}

	if(PIN_GetSyscallNumber(ctx,std) == 173 && PIN_GetSyscallArgument(ctx, std, 0) == 35){
		traceFile2 << "Traced: " << PIN_GetSyscallNumber(ctx,std) << " 0x35 -> Anti-Debugging: Executable is checking for SystemKernelDebuggerInformation\n";
	}


    traceFileAll << PIN_GetSyscallNumber(ctx, std) << "\n";
    /*for (int i = 0; i < 4; i++) {
        ADDRINT value = PIN_GetSyscallArgument(ctx, std, i);
        printf("  %d 0x%08x", value, value);
    }*/
	//traceFile2.close();
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
