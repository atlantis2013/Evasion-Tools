// GenerateReport.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string.h>

using namespace std;

void generateReport(){
	std::ofstream FinalReport;
	FinalReport.open("logs\\report.out");
	string line;

	ifstream system ("logs\\system.out");
	ifstream routines ("routines.out");
	ifstream shellCode ("shellCode.out");
	if (system.is_open())
	{
		while ( system.good() )
		{
			getline (system,line);
			FinalReport << line << endl;
		}
		system.close();
	}

	if (shellCode.is_open())
	{
		while ( shellCode.good() )
		{
			getline (shellCode,line);
			FinalReport << line << endl;
		}
		shellCode.close();
	}

	if (routines.is_open())
	{
		while ( routines.good() )
		{
			getline (routines,line);
			FinalReport << line << endl;
		}
		routines.close();
	}
}
int _tmain(int argc, _TCHAR* argv[])
{
	generateReport();
	return 0;
}

