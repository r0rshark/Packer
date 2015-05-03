// mypacker.cpp : definisce il punto di ingresso dell'applicazione console.
//

#include "stdafx.h"
#include "pe.h"
#include "debug.h"



PE pe;

void encrypt(isections *section, int val);

int _tmain(int argc, _TCHAR* argv[])
{
	char *input_path ="C:\\Users\\phate\\Desktop\\compiled.exe";
	char *output_path ="C:\\Users\\phate\\Desktop\\mypacked.exe";
	printf("loaded path %s\n",input_path);
	if (!pe_read(input_path, &pe)) {
		printf("Wrong PE format\n");
		return 0;
	}
	printf("PE has been read\n");

	DWORD oep = pe.EntryPoint;
	printf("OEP is %x",oep);
	//get the section containing the entry point
	int ep_section_number = getEntryPointSection(&pe);
	isections  *ep_section = &pe.m_sections[ep_section_number];
	//set the section writable	
	DEBUG(("old Entry Point Section Characteristics %x\n",ep_section->header.Characteristics));
	ep_section->header.Characteristics |= IMAGE_SCN_MEM_WRITE;
	DEBUG(("new Entry Point Section Characteristics %x\n",pe.m_sections[0].header.Characteristics));
	//Encrypting data
	DEBUG(("Entry Point Section before encrypting "));
	printSectionInfo(ep_section);
	encrypt(ep_section,0x01);
	DEBUG(("Entry Point Section after encrypting "));
	printSectionInfo(ep_section);

	if (!pe_write(output_path, &pe)) {
		printf("Error in writing PE \n");
		return 0;
	}
	printf("Encrypted PE successfully written in %s \n",output_path);

	return 0;
}

void encrypt(isections *section, int val){
	
	DEBUG(("Section EP has Data\n"));
	for (int i=0;i< section->header.SizeOfRawData;i++){
		section->data[i] = section->data[i] ^ val;
		}
	
	}


