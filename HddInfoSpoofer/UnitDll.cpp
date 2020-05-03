
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
PHOOK(ProcNtCreateFile)  HookNtCreateFile;
PHOOK(ProcNtDeviceIoControlFile) HookNtDeviceIoControlFile;


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
      wchar_t ProcPath[MAX_PATH];
      GetModuleFileNameW(NULL,ProcPath,countof(ProcPath)); 
      LDRLOG("Process path: %ls", &ProcPath);
      if(!NSTR::IsStrEqualIC(GetFileName(ProcPath), L"WmiPrvSE.exe"))return false;

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
// INIRefreshValueStr<PWSTR>(CFGSECNAME, L"DataPath", WorkFolder, DataSavePath, countof(DataSavePath), CfgFilePath);
 LOGMSG("Done");
}
//------------------------------------------------------------------------------------
bool _stdcall InitApplication(void)
{
 DBGMSG("Enter");
// HookNtCreateFile.SetHook("NtCreateFile","ntdll.dll"); 
 HookNtDeviceIoControlFile.SetHook("NtDeviceIoControlFile","ntdll.dll");
 DBGMSG("Done");
 return true;
}
//====================================================================================
//------------------------------------------------------------------------------------
int _stdcall GetDevGuidByHandle(HANDLE Hndl, PWSTR GuidStr)
{
 ULONG RetLen = 0;
 wchar_t NameBuf[512];
 NTSTATUS res = NtQueryObject(Hndl, ObjectNameInformation, &NameBuf, sizeof(NameBuf), &RetLen);
 if(res){LOGMSG("NtQueryObject failed with %08X", res);return -1;}
 UNICODE_STRING* str = (UNICODE_STRING*)&NameBuf;
 DBGMSG("Handle=%p, RetLen=%08X, Name='%ls'",Hndl,RetLen,str->Buffer);
 if(str->Length < (16*2))return -2;
 str->Buffer[str->Length/2] = 0;
 NSTR::StrCopy(GuidStr, &str->Buffer[8]);    // '\Device\0000003b'
 return 0;
}
//------------------------------------------------------------------------------------
int _stdcall RefrHddInfoIniStr(PWSTR SecID, PWSTR Name, LPSTR Value)
{
 wchar_t ValueBuf[512];
 int len = GetPrivateProfileStringW(SecID, Name, L"", ValueBuf, countof(ValueBuf), CfgFilePath);
 if(len <= 0)     // No value
  {
   NSTR::StrCopy(ValueBuf, Value);
   WritePrivateProfileStringW(SecID,Name,ValueBuf,CfgFilePath); 
   return 0;  // Created new
  } 
 if(NSTR::IsStrEqualSC(Value, ValueBuf))return 0;  // Same
 return NSTR::StrCopy(Value, ValueBuf);
}
//====================================================================================
//                            HOOKED  WINAPI
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtCreateFile(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength)
{                            
 if(!FileHandle || !ObjectAttributes || !ObjectAttributes->ObjectName || !ObjectAttributes->ObjectName->Buffer)return HookNtCreateFile.OrigProc(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);  // Some device?
 
 NTSTATUS res = HookNtCreateFile.OrigProc(FileHandle,DesiredAccess,ObjectAttributes,IoStatusBlock,AllocationSize,FileAttributes,ShareAccess,CreateDisposition,CreateOptions,EaBuffer,EaLength);
 DBGMSG("RetAddr=%p, Res=%08X, FileHandle=%p, DesiredAccess=%08X, FileAttributes=%08X, CreateDisposition=%08X, CreateOptions=%08X, Name=%ls", _ReturnAddress(),res, *FileHandle, DesiredAccess, FileAttributes, CreateDisposition, CreateOptions, ObjectAttributes->ObjectName->Buffer);

 return res;
} 
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)    
{
 wchar_t NameBuf[64];
 NTSTATUS res = HookNtDeviceIoControlFile.OrigProc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength); 
 DBGMSG("RetAddr=%p, Res=%08X, FileHandle=%p, IoControlCode=%08X, InputBuffer=%p, OutputBuffer=%p, InputBufferLength=%08X, OutputBufferLength=%08X, Event=%p, ApcContext=%p, ApcRoutine=%p, IoStatusBlock=%p",_ReturnAddress(),res,FileHandle,IoControlCode,InputBuffer,OutputBuffer,InputBufferLength,OutputBufferLength,Event,ApcContext,ApcRoutine,IoStatusBlock);
 if(res)return res;  // Error
 if((IoControlCode == IOCTL_STORAGE_GET_DEVICE_NUMBER) && OutputBuffer)    // Not a WMI serial number ("DeviceID","Caption","Name","Description")
  {
   STORAGE_DEVICE_NUMBER* dn = (STORAGE_DEVICE_NUMBER*)OutputBuffer;
   DBGMSG("IOCTL_STORAGE_GET_DEVICE_NUMBER: DeviceType=%08X, DeviceNumber=%08X, PartitionNumber=%08X",dn->DeviceType, dn->DeviceNumber, dn->PartitionNumber);
   if(dn->DeviceType != FILE_DEVICE_DISK)return res;   // Not a HDD
   if(GetDevGuidByHandle(FileHandle, NameBuf) < 0)return res;

   char TmpNum[64];
   ConvertToHexStr(dn->DeviceNumber, 8, TmpNum, true, NULL);
   RefrHddInfoIniStr(NameBuf, L"DeviceID", TmpNum);
   LOGMSG("Replacing DeviceID with %s", &TmpNum); 
   dn->DeviceNumber = HexStrToNum<DWORD>(TmpNum);
  }

 if((IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) && OutputBuffer && InputBuffer && (((STORAGE_PROPERTY_QUERY*)InputBuffer)->PropertyId == StorageDeviceProperty))   // QueryType==0 is "Instructs the port driver to report a device descriptor, an adapter descriptor or a unique hardware device ID (DUID). "
  {
   STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)OutputBuffer;
   LPSTR VendorId        = desc->VendorIdOffset ? ((LPSTR)desc + desc->VendorIdOffset): "";
   LPSTR ProductId       = desc->ProductIdOffset ? ((LPSTR)desc + desc->ProductIdOffset): "";
   LPSTR ProductRevision = desc->ProductRevisionOffset ? ((LPSTR)desc + desc->ProductRevisionOffset): "";
   LPSTR SerialNumber    = desc->SerialNumberOffset ? ((LPSTR)desc + desc->SerialNumberOffset): "";
   DBGMSG("IOCTL_STORAGE_QUERY_PROPERTY: DeviceType=%u, DeviceTypeModifier=%u, RawPropertiesLength=%08X, VendorId='%s', ProductId='%s', ProductRevision='%s', SerialNumber='%s'",desc->DeviceType, desc->DeviceTypeModifier, desc->RawPropertiesLength, VendorId,ProductId,ProductRevision,SerialNumber);
   if(GetDevGuidByHandle(FileHandle, NameBuf) < 0)return res;

   LPSTR Base = (LPSTR)desc;
   UINT BaseOffs = desc->RawPropertiesLength + (sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1);     // NOTE: STORAGE_DEVICE_DESCRIPTOR validation will fail!
   char TmpVal[512];

   NSTR::StrCopy(TmpVal, VendorId);
   if(int vlen = RefrHddInfoIniStr(NameBuf, L"VendorId", TmpVal))
    {
     LOGMSG("Replacing VendorId with '%s'", &TmpVal);  
     desc->VendorIdOffset = BaseOffs;
     memcpy(&Base[BaseOffs], &TmpVal, vlen + 1);
     BaseOffs += vlen + 1;
    }

   NSTR::StrCopy(TmpVal, ProductId);
   if(int vlen = RefrHddInfoIniStr(NameBuf, L"ProductId", TmpVal))
    {
     LOGMSG("Replacing ProductId with '%s'", &TmpVal); 
     desc->ProductIdOffset = BaseOffs;
     memcpy(&Base[BaseOffs], &TmpVal, vlen + 1);
     BaseOffs += vlen + 1;     
    }

   NSTR::StrCopy(TmpVal, ProductRevision);
   if(int vlen = RefrHddInfoIniStr(NameBuf, L"ProductRevision", TmpVal))
    {
     LOGMSG("Replacing ProductRevision with '%s'", &TmpVal);
     desc->ProductRevisionOffset = BaseOffs;
     memcpy(&Base[BaseOffs], &TmpVal, vlen + 1);
     BaseOffs += vlen + 1;     
    }

   NSTR::StrCopy(TmpVal, SerialNumber);
   if(int vlen = RefrHddInfoIniStr(NameBuf, L"SerialNumber", TmpVal))
    {
     LOGMSG("Replacing SerialNumber with '%s'", &TmpVal);  
     desc->SerialNumberOffset = BaseOffs;
     memcpy(&Base[BaseOffs], &TmpVal, vlen + 1);
     BaseOffs += vlen + 1;
    }

   desc->RawPropertiesLength = BaseOffs - (sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1);    
   //IoStatusBlock->Information->   // TODO: Update BytesReturned?
  }
 return res;    
}
//------------------------------------------------------------------------------------
//====================================================================================
