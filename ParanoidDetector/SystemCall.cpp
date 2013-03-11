/*
    Author:     Lim Seok Min
    Email:      a0073541@nus.edu.sg
    Purpose:    This tool will return all the routines called by the program.

    Reference:  http://jbremer.org/malware-unpacking-level-pintool/#rp-syscall
*/

#include "SystemCall.h"
typedef struct SysCallID{
	ADDRINT _name;
	struct SysCallID * _next;
}SYSCALLID;

typedef struct NtQueryInformationProcess{
	ADDRINT processhandle;
	ADDRINT ProcessInformationClass; // we want this only
}NTQUERYINFORMATIONPROCESS;
	
SYSCALLID *SysList = 0;

VOID SystemFini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("result.out", ios::app | ios::out);
	
    for (SYSCALLID * rc = SysList; rc; rc = rc->_next)
    {
		//outFile << rc->_name << endl;
    }

	outFile.close();
   
}

void syscall_entry(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
	ofstream outFile;
	outFile.open("systemCall.out", ios::app | ios::out);

	SYSCALLID *rc = new SYSCALLID;
    rc->_name = PIN_GetSyscallNumber(ctx, std);
    // Add to list of routines
    rc->_next = SysList;
    SysList = rc;
	
	// Process checks for ProcessDebugPort --> This is windows 7
	// windows xp: 154
	if(rc->_name == 234 && PIN_GetSyscallArgument(ctx, std, 1) == 7){
		cout << "System Call ID: " << rc->_name << "\n";
		printf("Process Handle-> %d 0x%08x\n",PIN_GetSyscallArgument(ctx, std, 0), PIN_GetSyscallArgument(ctx, std, 0));
		printf("Process Info-> %d 0x%08x\n", PIN_GetSyscallArgument(ctx, std, 1), PIN_GetSyscallArgument(ctx, std, 1));
		outFile << "Binary is checking ProcessDebugPort at offset " << PIN_GetSyscallArgument(ctx, std, 1) << "\n";
	}

	// Process checks for detaching debugger
	// windows xp: 228
	if(rc->_name == 335 && PIN_GetSyscallArgument(ctx, std, 1) == 0x11){
		cout << "System Call ID: " << rc->_name << "\n";
		printf("Process Handle-> %d 0x%08x\n",PIN_GetSyscallArgument(ctx, std, 0), PIN_GetSyscallArgument(ctx, std, 0));
		printf("Process Info-> %d 0x%08x\n", PIN_GetSyscallArgument(ctx, std, 1), PIN_GetSyscallArgument(ctx, std, 1));
		
		outFile << "Binary is detaching debugger.\n";
	}

}
 
void syscall_exit(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
   ADDRINT return_value = PIN_GetSyscallReturn(ctx, std);
  //  printf(", return-value: %d 0x%08x\n", return_value,
   //     return_value);
}