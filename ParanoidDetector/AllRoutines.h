/*
    Author:     Lim Seok Min
    Email:      a0073541@nus.edu.sg
    Purpose:    This tool will return all the routines called by the program.

    Reference:  Modified from proccount.cpp 
*/
#pragma once
#include "main.h"

const char * StripPath(const char * path);
VOID Routine(RTN rtn, VOID *v);
VOID RoutinesFini(INT32 code, VOID *v);
int mainRoutine();