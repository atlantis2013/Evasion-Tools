#pragma once
#include "main.h"

void syscall_entry(THREADID thread_id, CONTEXT *ctx,
	SYSCALL_STANDARD std, void *v);

void syscall_exit(THREADID thread_id, CONTEXT *ctx,
	SYSCALL_STANDARD std, void *v);

void SystemCallfini(INT32, VOID*);
void setTraceFile(string file);

//std::ofstream traceFile2;