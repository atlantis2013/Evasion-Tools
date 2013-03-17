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

std::string prevInst;

// NTGlobalFlag
bool NTGlobalFlag = 0;
string NTGlobalInstr = "";

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
std::string dumpInstruction(INS ins)
{
		std::stringstream ss;

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

		// Look up call information for direct calls
		if (INS_IsCall(ins) && INS_IsDirectBranchOrCall(ins))
		{
			ss << " -> " << RTN_FindNameByAddress(INS_DirectBranchOrCallTargetAddress(ins));
		}

		return ss.str();
}

/*
*	Detect what we want to detect and write to our file
*
*/
void detect(std::string thisItr){
	// Anti-VM
	if(thisItr.find("0F 01 E0") != thisItr.npos){
		if(prevInst.find("B8 CC CC CC CC") != prevInst.npos){
			shellTraceFile << "========================= Anti-VM: SMSW technique =========================\n";
			shellTraceFile << prevInst << "\n";
			shellTraceFile << thisItr << "\n\n";
		}
	}

	if(thisItr.find("81 7D F4 00 00 AD DE") != thisItr.npos){
		if(prevInst.find("0F 00 45 F4") != prevInst.npos){
			shellTraceFile << "========================= Anti-VM: SLDT technique =========================\n";
			shellTraceFile << prevInst << "\n";
			shellTraceFile << thisItr << "\n\n";
		}
	}

	if(thisItr.find("0F 01 4D F4") != thisItr.npos){
		shellTraceFile << "========================= Anti-VM: SIDT/Redpill technique =========================\n";
		shellTraceFile << thisItr << "\n\n";
	}

	if(thisItr.find("81 FB 68 58 4D 56") != thisItr.npos){
		if(prevInst.find("ED") != prevInst.npos){
			shellTraceFile << "========================= Anti-VM: IN technique =========================\n";
			shellTraceFile << prevInst << "\n";
			shellTraceFile << thisItr << "\n\n";
		}
	}

	if(thisItr.find("RtlGetNtGlobalFlags") != thisItr.npos){
		NTGlobalInstr = thisItr;
		NTGlobalFlag = 1;
	}

	if(NTGlobalFlag && thisItr.find("8B 40 68") != thisItr.npos){
		if(prevInst.find("8B 40 30") != prevInst.npos){
			shellTraceFile << "========================= Anti-Debug: NtGlobalFlags technique =========================\n";
			shellTraceFile << NTGlobalInstr << "\n";
			shellTraceFile << prevInst << "\n";
			shellTraceFile << thisItr << "\n\n";
		}
	}

	if(thisItr.find("83 78 10") != thisItr.npos){
		if(prevInst.find("8B 40 10") != prevInst.npos){
			shellTraceFile << "========================= Anti-Debug:  HeapFlag technique =========================\n";
			shellTraceFile << prevInst << "\n";
			shellTraceFile << thisItr << "\n\n";
		}
	}
	// Anti-Debugging
}

void dump_shellcode(std::string* instructionString)
{
	if (!legitInstructions.empty())
	{
		prevInst = "";	
		for (std::list<std::string>::iterator Iter = legitInstructions.begin(); Iter != legitInstructions.end(); ++Iter)
		{
			if(*Iter!=""){
				traceFile << *Iter << endl;
				detect(*Iter);
				prevInst = *Iter;
			}
		}
		legitInstructions.clear();
	}
}


void traceInst(INS ins, VOID*)
{
	ADDRINT address = INS_Address(ins);

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
	shellTraceFile.close();
}

int mainShellCode()
{
    traceFile.open(outputFile.Value().c_str());
    
    INS_AddInstrumentFunction(traceInst, 0);
    PIN_AddFiniFunction(fini, 0);

    return 0;
}
