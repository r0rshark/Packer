/*	pe.cpp - portable executable builder

	Copyright (C) 2009  Soner Köksal <renos@w.cn>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "pe.h"
#include "debug.h"

#define align(_size, _base_size) \
    (((_size + _base_size - 1) / _base_size) * _base_size)
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe)
{
	DWORD idx = pe->int_headers.FileHeader.NumberOfSections;
	DWORD dwSectionSize = _section_size;

    pe->int_headers.FileHeader.NumberOfSections++;
    pe->m_sections = (isections*) realloc(pe->m_sections, pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));
    memset(&pe->m_sections[idx], 0x00, sizeof(isections));
    pe->m_sections[idx].data = (BYTE*) malloc(align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
	pe->m_sections[idx].header.PointerToRawData = align(pe->m_sections[idx - 1].header.PointerToRawData + pe->m_sections[idx - 1].header.SizeOfRawData, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.VirtualAddress = align(pe->m_sections[idx - 1].header.VirtualAddress + pe->m_sections[idx - 1].header.Misc.VirtualSize, pe->int_headers.OptionalHeader.SectionAlignment);
	pe->m_sections[idx].header.SizeOfRawData = align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment);
	pe->m_sections[idx].header.Misc.VirtualSize = dwSectionSize;
	pe->m_sections[idx].header.Characteristics  = 0xE0000040;
	sprintf((char*) pe->m_sections[idx].header.Name, "%s", sname);

    memset(pe->m_sections[idx].data, 0x00, align(dwSectionSize, pe->int_headers.OptionalHeader.FileAlignment));
    memcpy(pe->m_sections[idx].data, _section, _section_size);

    pe->int_headers.OptionalHeader.AddressOfEntryPoint = pe->m_sections[idx].header.VirtualAddress + _entry_point_offset;
}

int pe_read(const char* filename, PE *pe)
{
    FILE *hFile = fopen(filename, "rb");
    if(!hFile)
        return 0;

    fread(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);

    if(pe->m_dos.header.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if(pe->m_dos.stub_size)
	{
		pe->m_dos.stub = (BYTE*) malloc(pe->m_dos.stub_size);
		fread(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);
	}

    fread(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);

    if(pe->int_headers.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    pe->m_sections = (isections*) malloc(pe->int_headers.FileHeader.NumberOfSections * sizeof(isections));

    for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
        fread(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);

    for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
    {
        if(pe->m_sections[i].header.SizeOfRawData)
        {
            fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
            pe->m_sections[i].data = (BYTE*) malloc(pe->m_sections[i].header.SizeOfRawData);
            fread(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
        }
    }

    pe->EntryPoint = pe->int_headers.OptionalHeader.AddressOfEntryPoint + pe->int_headers.OptionalHeader.ImageBase;

    fclose(hFile);

    return 1;
}

int pe_write(const char* filename, PE *pe)
{
    FILE *hFile = fopen(filename, "wb");
    if(!hFile)
        return 0;

    fwrite(&pe->m_dos.header, sizeof(IMAGE_DOS_HEADER), 1, hFile);

	pe->m_dos.stub_size = pe->m_dos.header.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if(pe->m_dos.stub_size)
        fwrite(pe->m_dos.stub, pe->m_dos.stub_size, 1, hFile);

    pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = NULL;
    pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = NULL;
    pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = NULL;
    pe->int_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = NULL;

    pe->int_headers.OptionalHeader.SizeOfImage = pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.VirtualAddress + pe->m_sections[pe->int_headers.FileHeader.NumberOfSections - 1].header.Misc.VirtualSize;
        fwrite(&pe->int_headers, sizeof(IMAGE_NT_HEADERS), 1, hFile);

    fseek(hFile, pe->m_dos.header.e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);
    for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
        fwrite(&pe->m_sections[i].header, sizeof(IMAGE_SECTION_HEADER), 1, hFile);

    for(int i = 0; i < pe->int_headers.FileHeader.NumberOfSections; i++)
    {

        printf("[%d]Name: %s\n", i, pe->m_sections[i].header.Name);
        printf("\tPointerToRawData: 0x%X\n", pe->m_sections[i].header.PointerToRawData);
        printf("\tVirtualAddress: 0x%X\n", pe->m_sections[i].header.VirtualAddress);
        printf("\tSizeOfRawData: 0x%X\n", pe->m_sections[i].header.SizeOfRawData);
        printf("\tCharacteristics: 0x%X\n\n", pe->m_sections[i].header.Characteristics);
        if(pe->m_sections[i].header.SizeOfRawData)
        {
            fseek(hFile, pe->m_sections[i].header.PointerToRawData, SEEK_SET);
            fwrite(pe->m_sections[i].data, pe->m_sections[i].header.SizeOfRawData, 1, hFile);
        }
    }

    printf("Old Entry Point: 0x%X\n", pe->EntryPoint);
    printf("New Entry Point: 0x%X\n\n", pe->int_headers.OptionalHeader.ImageBase + pe->int_headers.OptionalHeader.AddressOfEntryPoint);

    fclose(hFile);

    return 1;
}

int getEntryPointSection(PE *pe){

	int rva_oep = pe->int_headers.OptionalHeader.AddressOfEntryPoint;
	#ifdef _DEBUG
		printf("RVA Address of Entry Point %x\n",rva_oep);
	#endif
	
	for(int i=0; i < pe->int_headers.FileHeader.NumberOfSections; i++){
		isections current_section = pe->m_sections[i];
		int rva_current_section = current_section.header.VirtualAddress;
		//NB I am using size of Raw data but I should have used Virtual Size but this value is not present probably it should be calculated using alignments
		int size_current_section = current_section.header.SizeOfRawData; 
		
		DEBUG(("Section number %d has Virtual address hex %x\n",i,rva_current_section));
		DEBUG(("Section number %d has Raw size hex %x\n",i,size_current_section));
		DEBUG(("Section number %d has csize size hex %x\n",i,current_section.csize));
		
		//check if Entry point belongs to this section
		if(rva_oep>=rva_current_section && rva_oep<=rva_current_section+size_current_section){
			printf("Found Entry point with rva %x in section number %d start at %x has size hex %x\n",rva_oep,i,rva_current_section,size_current_section);
			return i;
		}
		

	}
}

void printSectionInfo(isections *section){
	int rva_current_section = section->header.VirtualAddress;
	int size_current_section = section->header.SizeOfRawData; 
	DEBUG(("Section starts at %x and has Raw Data of %x\n",rva_current_section,size_current_section));
	DEBUG(("Content of Section:\n"));
	for (int i=0;i< section->header.SizeOfRawData;i++){
			DEBUG(("%x ",section->data[i]));
	}
}