/*	pe.h - portable executable builder definitons

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

#ifndef _PE_H
#define _PE_H

#include "stdio.h"
#include "windows.h"

typedef struct dos_section
{
    IMAGE_DOS_HEADER header;
    DWORD stub_size;
    BYTE *stub;
};

typedef struct isections
{
    IMAGE_SECTION_HEADER header;
    BYTE *data;
    DWORD csize;
    BYTE *cdata;
};

typedef struct dllexps
{
    IMAGE_EXPORT_DIRECTORY expdir;
    char **Names;
    DWORD *Functions;
    WORD *NameOrdinals;
};

typedef struct uncomresc
{
    LPVOID rescdata;
    DWORD rescinfo;
};

typedef struct PE
{
    DWORD EntryPoint;
    dos_section m_dos;
    LPVOID comparray;
    DWORD scomparray;
    char **dlls;
    char **thunks;
    DWORD sdllimports;
    DWORD rescaddress;
    dllexps dllexports;
    DWORD sdllexports;
    uncomresc *uncompresource;
    DWORD cuncompresource;
    DWORD suncompresource;
    IMAGE_NT_HEADERS int_headers;
    isections *m_sections;
};

int pe_read(const char* filename, PE *pe);
int pe_write(const char* filename, PE *pe);
void AddSection(const char* sname, LPVOID _section, DWORD _section_size, DWORD _entry_point_offset, PE *pe);
//return the number of the section containing the Entry Point
int getEntryPointSection(PE *pe);
void printSectionInfo(isections *section);


#endif /* _PE_H */
