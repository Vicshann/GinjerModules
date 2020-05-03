
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

//====================================================================================
#pragma comment(linker,"/ENTRY:DLLMain")
#pragma comment(linker,"/NODEFAULTLIB")

// ---------- SETTINGS ------------------

                         
//---------------------------------------
//PHOOK(ProcNtCreateFile)  HookNtCreateFile;
//PHOOK(ProcNtDeviceIoControlFile) HookNtDeviceIoControlFile;


// NtCurrentTeb()->LastErrorValue = SInjModDesc*  (Always fits into 32 bits, valid if > 65535)

wchar_t WorkFolder[MAX_PATH];
wchar_t CfgFilePath[MAX_PATH];  
wchar_t DataSavePath[MAX_PATH];

// TODO: Share key (CTRL+ALT+D) combination and show all injected processes and their modules


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
      wchar_t ProcPath[MAX_PATH];
      GetModuleFileNameW(NULL,ProcPath,countof(ProcPath)); 
      LDRLOG("Process path: %ls", &ProcPath);
//      if(!NSTR::IsStrEqualIC(GetFileName(ProcPath), L"WmiPrvSE.exe"))return false;

      GetModuleFileNameW(hModule,WorkFolder,countof(WorkFolder)); 
      lstrcpyW(LogFilePath, WorkFolder);
      lstrcpyW(CfgFilePath, WorkFolder);
      PWSTR ExtPtr = GetFileExt(WorkFolder);
      ExtPtr[-1] = '\\';  //  TrimFilePath(WorkFolder);
      *ExtPtr = 0;
      lstrcpyW(GetFileExt(LogFilePath),L"log");
      lstrcpyW(GetFileExt(CfgFilePath),L"ini");
      LoadConfiguration();
      LOGMSG("Process path: %ls",&ProcPath);
      InitApplication();
      Sleep(8000);    // NtSuspendProcess
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
 return true;    // Always fail after dump to not stay loaded
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
bool _stdcall InitApplication(void)
{
 DBGMSG("Enter");
// HookNtCreateFile.SetHook("NtCreateFile","ntdll.dll"); 
// HookNtDeviceIoControlFile.SetHook("NtDeviceIoControlFile","ntdll.dll");
 DBGMSG("Done");
 return true;
}
//====================================================================================

//------------------------------------------------------------------------------------

//====================================================================================
//                            HOOKED  WINAPI
//------------------------------------------------------------------------------------
//====================================================================================
