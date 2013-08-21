#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <set>
#include <list>
#include <sstream>

std::list<std::string> legitInstructions;
std::set<std::string*> dumped;
std::ofstream traceFile;
KNOB<string> outputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "logs\\allShellcode.out", "specify trace file name");
ofstream shellTraceFile("logs\\shellCode.out");

std::string prevInst="";

std::ofstream TraceAntiDebug3;
std::ofstream TraceAntiVirtual3;
std::ofstream TraceAntiSandbox3;
// NTGlobalFlag
bool NTGlobalFlag = 0;
string NTGlobalInstr = "";
int inDetect = 0;

bool isUnknownAddress(ADDRINT address)
{
	for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
	{
		for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
			{
				return false;
			}
		}
	}

	return true;
}
/*
*	Detect what we want to detect and write to our file
*
*/
void detect(std::string thisItr){
	// Anti-VirtualPC, if eax is invalid
	if(thisItr.find("ret") != thisItr.npos){
		if(prevInst.find("mov eax, 1") != prevInst.npos){
			TraceAntiVirtual3 << thisItr << endl;
			TraceAntiVirtual3 << "Anti-VirtualBox:	ret/mov eax, 1 detected. Detected Invalid Technique\n" << endl;
		}
	}

	if(thisItr.find("0f3f070b") != thisItr.npos){
		if(prevInst.find("mov eax, 1") != prevInst.npos){
			TraceAntiVirtual3 << thisItr << endl;
			TraceAntiVirtual3 << "Anti-VirtualPC:		0f3f070b spotted. Detected Invalid Instruction Technique\n" << endl;
		}
	}

	// Anti-VM
	if(thisItr.find("0F 01 E0") != thisItr.npos){
		if(prevInst.find("B8 CC CC CC CC") != prevInst.npos){
			TraceAntiVirtual3 << thisItr << endl;
			TraceAntiVirtual3 << "Anti-VMWare:		smsw eax spotted. Detected the SMSW Technique\n"  << endl;
		}
	}

	if(thisItr.find("0xdead0000") != thisItr.npos){
			TraceAntiVirtual3 << thisItr << endl;
			TraceAntiVirtual3 << "Anti-VMWare:		0xdead0000 spotted. Detected the SLDT Technique\n" << endl;
	}

	if(thisItr.find("sidt ") != thisItr.npos){
		TraceAntiVirtual3 << thisItr << endl;
		TraceAntiVirtual3 << "Anti-VMWare:		SIDT spotted. Detected the SIDT/Redpill Technique\n" << endl;
	}
	if(thisItr.find("0x564d5868") != thisItr.npos){
		TraceAntiVirtual3 << thisItr << endl;
		TraceAntiVirtual3 << "Anti-VMWare:  ";
		TraceAntiVirtual3 << "	0x564d5868 spotted. Detected the IN Technique\n" << endl;
	}

}

std::string dumpInstruction(INS ins)
{
		std::stringstream ss, instss;

		ADDRINT address = INS_Address(ins);

		// Generate address and module information
		ss << "0x" << setfill('0') << setw(8) << uppercase << hex << address << " " ;

		// Generate instruction byte encoding
		for (int i=0;i<INS_Size(ins);i++)
		{
			ss << setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF) << " ";
		}

		for (int i=INS_Size(ins);i<12;i++)
		{
			ss << " ";
		}

		// Generate diassembled string
		ss << INS_Disassemble(ins);
		instss << INS_Disassemble(ins);

		

		// Look up call information for direct calls
		if (INS_IsCall(ins) && INS_IsDirectBranchOrCall(ins))
		{
			ss << " -> " << RTN_FindNameByAddress(INS_DirectBranchOrCallTargetAddress(ins));
		}

		// write all shellcode to one file
		shellTraceFile << ss.str() << endl;

		// we should do the detection here.
		prevInst = ss.str();
		detect(ss.str());
		return ss.str();
}


void dump_shellcode(std::string* instructionString)
{
	if (!legitInstructions.empty())
	{
		for (std::list<std::string>::iterator Iter = legitInstructions.begin(); Iter != legitInstructions.end(); ++Iter)
		{
			if(*Iter!=""){
				traceFile << *Iter << endl;
				//detect(*Iter);
			}
		}
		legitInstructions.clear();
	}
}


void traceInst(INS ins, VOID*)
{
	ADDRINT address = INS_Address(ins);
	std::stringstream ss;

	if (isUnknownAddress(address))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dump_shellcode),
			IARG_PTR, new std::string(dumpInstruction(ins)), IARG_END
		);
	}
	else
	{
		legitInstructions.push_back(dumpInstruction(ins));
	}


}



VOID fini(INT32, VOID*)
{
    traceFile.close();
	//shellTraceFile.close();
	//generateReport();
}

int mainShellCode()
{
	TraceAntiDebug3.open("logs\\antidebug_shellCode.out");
	TraceAntiVirtual3.open("logs\\antivirtual_shellCode.out");
	TraceAntiSandbox3.open("logs\\antisandbox_shellCode.out");
    //traceFile.open(outputFile.Value().c_str());
    
    INS_AddInstrumentFunction(traceInst, 0);
    PIN_AddFiniFunction(fini, 0);
    return 0;
}
