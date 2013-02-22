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


SYSCALLID *SysList = 0;

VOID SystemFini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("result.out", ios::app | ios::out);
	
	outFile << "=================== SYSTEM CALL =================" << endl;
		
    for (SYSCALLID * rc = SysList; rc; rc = rc->_next)
    {
		outFile << rc->_name << endl;
    }
	outFile << "=================== END OF SYSTEM CALL =================" << endl;
    
}

void syscall_entry(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
	SYSCALLID *rc = new SYSCALLID;
    rc->_name = PIN_GetSyscallNumber(ctx, std);
    // Add to list of routines
    rc->_next = SysList;
    SysList = rc;

    /*for (int i = 0; i < 4; i++) {
        ADDRINT value = PIN_GetSyscallArgument(ctx, std, i);
		printf("  %d 0x%08x", value, value);
    }*/
}
 
void syscall_exit(THREADID thread_id, CONTEXT *ctx,
    SYSCALL_STANDARD std, void *v)
{
   // ADDRINT return_value = PIN_GetSyscallReturn(ctx, std);
   // printf(", return-value: %d 0x%08x\n", return_value,
    //    return_value);
}