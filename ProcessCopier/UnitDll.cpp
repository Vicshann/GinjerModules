
/*
  Copyright (c) 2018 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "UnitDll.h"

// DESCRIPTION: Silently copies any started executable and all its DLLs
//====================================================================================
#pragma comment(linker,"/ENTRY:DLLMain")
#pragma comment(linker,"/NODEFAULTLIB")

// ---------- SETTINGS ------------------

                         
//---------------------------------------
// NtCurrentTeb()->LastErrorValue = SInjModDesc*  (Always fits into 32 bits, valid if > 65535)

wchar_t WorkFolder[MAX_PATH];
wchar_t CfgFilePath[MAX_PATH];  
wchar_t DataSavePath[MAX_PATH];

// Reflective load:
//     hModule    = Module Base
//     ReasonCall = 15
//     lpReserved = SInjModDesc*  (Can be used to find SBlkDescr*)
//===========================================================================
BOOL APIENTRY DLLMain(HMODULE hModule, DWORD ReasonCall, LPVOID lpReserved) 
{
 SModDesc* ModDesc = ModDescFromCurTh();        // NULL if loaded not by GInjer
 SBlkDesc* BlkDesc = AddrToBlkDesc(ModDesc);
 SLdrDesc* LdrDesc = GetCurLdrDesc(BlkDesc); 
 bool RemTh = (DWORD)hModule & NInjLdr::RemThModMarker;      // DLLMain has been passed to CreateRemoteThread. Normal HMODULE would be aligned at 0x1000  
 if(RemTh || (ReasonCall >= DLL_REFLECTIVE_LOAD)) 
  {
   hModule    = (HMODULE)NInjLdr::ReflectiveRelocateSelf(hModule, (LdrDesc)?((PVOID)LdrDesc->NtDllBase):(NULL));                           
   ReasonCall = DLL_PROCESS_ATTACH;   
  } 
 if(ModDesc){LdrLogInit(ModDesc); LDRLOG("Hello from %08X: %ls", ModDesc->Flags, &ModDesc->ModulePath);}
 switch(ReasonCall)	    
  {			 
   case DLL_PROCESS_ATTACH:
     {
      GetModuleFileNameW(hModule,WorkFolder,countof(WorkFolder)); 
      lstrcpyW(LogFilePath, WorkFolder);
      lstrcpyW(CfgFilePath, WorkFolder);
      PWSTR ExtPtr = GetFileExt(WorkFolder);
      ExtPtr[-1] = '\\';  //  TrimFilePath(WorkFolder);
      *ExtPtr = 0;
      lstrcpyW(GetFileExt(LogFilePath),L"log");
      lstrcpyW(GetFileExt(CfgFilePath),L"ini");
      LoadConfiguration();
      DumpProcessFolder();
     }
     break;									
   case DLL_THREAD_ATTACH:
     break; 
   case DLL_THREAD_DETACH:
     break;
   case DLL_PROCESS_DETACH:       
	 break;
   case DLL_REFLECTIVE_LOAD:  
     break;

   default : return false;  // WRONG REASON CODE !!!!!!
  }
 return false;    // Always fail after dump to not stay loaded
}
//====================================================================================
void _stdcall LoadConfiguration(void)
{                      
 LOGMSG("Entering...");
 LogMode      = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"LogMode", lmNone, CfgFilePath); 
 INIRefreshValueStr<PWSTR>(CFGSECNAME, L"DataPath", WorkFolder, DataSavePath, countof(DataSavePath), CfgFilePath);
 LOGMSG("Done");
}
//------------------------------------------------------------------------------------
bool _stdcall CopyFolderW(PWSTR FolderPath, PWSTR DstRootPath, UINT ProcRootOffset, UINT DstRoolLen)
{
 DWORD  PathLen;
 HANDLE hSearch;
 WIN32_FIND_DATAW fdat;
 WCHAR  PathBuffer[MAX_PATH];

 LOGMSG("FolderPath: %ls", FolderPath);
 PathBuffer[0] = 0;
 lstrcatW(PathBuffer,FolderPath);
 PathLen = lstrlenW(PathBuffer);
 if(IsFilePathDelim(PathBuffer[PathLen-1]))PathLen--;
 PathBuffer[PathLen+0] = '\\';
 PathBuffer[PathLen+1] = '*';
 PathBuffer[PathLen+2] = 00;
 hSearch = FindFirstFileW(PathBuffer,&fdat);
 if(hSearch == INVALID_HANDLE_VALUE)return false;
 do
  {    
   if((fdat.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && IsPathLink(&fdat.cFileName[0]))continue;  // Not a real directory
   PathBuffer[PathLen+1] = 0;
   lstrcatW(PathBuffer,fdat.cFileName);
   if(fdat.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)CopyFolderW(PathBuffer, DstRootPath, ProcRootOffset, DstRoolLen);  
    else   // Copy file
    {
     lstrcpyW(&DstRootPath[DstRoolLen], &PathBuffer[ProcRootOffset+1]);    
 //    if(GetFileAttributesW(DstRootPath) != INVALID_FILE_ATTRIBUTES)continue;
     LOGMSG("Copying from '%ls' to '%ls'", &PathBuffer, DstRootPath);
     CreateDirectoryPath(DstRootPath);
     CopyFileW(PathBuffer, DstRootPath, TRUE);	 
    }
  }
   while(FindNextFileW(hSearch,&fdat));
 FindClose(hSearch);
 return true;
}
//---------------------------------------------------------------------------
int _stdcall DumpProcessFolder(void)
{ 
 wchar_t SavePath[MAX_PATH];
 wchar_t ProcessPath[MAX_PATH];
 LOGMSG("Entering...");
 HMODULE hProcessMod = GetModuleHandleW(NULL);
 if(!hProcessMod)return -1;
 lstrcpyW(SavePath, DataSavePath);
 UINT PLen = GetModuleFileNameW(hProcessMod,ProcessPath,countof(ProcessPath));
 lstrcatW(SavePath, GetFileName(ProcessPath));
 GetFileExt(SavePath)[-1] = 0;
 lstrcatW(SavePath, L"\\");
 PLen = TrimFilePath(ProcessPath) -1;
 while((ProcessPath[PLen] != '\\')&&(ProcessPath[PLen] != '//'))PLen--;
 UINT DLen = lstrlenW(SavePath);
 LOGMSG("ProcessPath: %ls", &ProcessPath);
 LOGMSG("DataSavePath: %ls", &SavePath);
 CopyFolderW(ProcessPath, SavePath, PLen, DLen);
 LOGMSG("Done");
 return 0;  
}
//====================================================================================

//====================================================================================
