
//#define KERNELDRV

enum ELogModes {lmNone=0,lmFile=0x01,lmCons=0x02,lmProc=0x04,lmFileUpd=0x08};
enum ELogFlags {lfNone=0,lfLineBreak=0x01,lfLogName=0x02,lfLogTime=0x04,lfLogThID=0x08,lfLogMsgIdx=0x10,lfRawTextMsg=0x20};


#ifdef __BORLANDC__
#define _PRNM_ __FUNC__
#else
#define _PRNM_ __FUNCTION__
#endif


extern void  _cdecl LogProc(int Flags, char* ProcName, char* Message, ...);
#define LOGMSG(msg,...) LogProc(lfLineBreak|lfLogName|lfLogTime|lfLogThID,_PRNM_,msg,__VA_ARGS__)      // TODO: LogSafe or LogFast
#define DBGMSG LOGMSG


#ifdef KERNELDRV
extern "C" 
{
#include <ntddk.h>
#include <basetsd.h>
#include <windef.h>

#if !defined(_M_X64)
__int64 _InterlockedCompareExchange64(__int64 volatile * _Destination, __int64 _Exchange, __int64 _Comparand);
#endif
}


#pragma function(memset)
#pragma function(memcpy)

#include "DrvFormatPE.h"
#else
#include <windows.h>
#include <intrin.h>
#include "OldFormatPE.h"
#endif


#include "HDE.hpp"

#ifndef KERNELDRV

static NTSTATUS (NTAPI *pZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) = 0;

bool _stdcall IsWow64Sys(void)
{
 static PVOID Proc = NULL;
 if(!Proc)Proc = GetProcAddress(GetModuleHandle("Kernel32.dll"),"IsWow64Process");
 if(!Proc)return false;
 BOOL Result = 0;
 return ((BOOL (_stdcall *)(HANDLE,PBOOL))Proc) (GetCurrentProcess(), &Result) && Result;
}

#else
//---------------------------------------------------------------------------
/*static PVOID _stdcall GetSystemRoutineAddress(CHAR *ProcName) 
{
 UNICODE_STRING ustr; 
 WCHAR Name[256];

 ustr.Buffer = (PWSTR)&Name;
 ustr.Length = ustr.MaximumLength = 0;
 for(int ctr=0;ProcName[ctr] && (ctr < ((sizeof(Name)/2)-1));ctr++){Name[ctr] = ProcName[ctr];ustr.Length = ++ustr.MaximumLength;}
 ustr.Buffer[ustr.Length] = 0;
 ustr.Length = ustr.MaximumLength = ustr.Length * 2;
 return MmGetSystemRoutineAddress(&ustr);   
} */
#endif
//------------------------------------------------------------------------------------------------------------
template<typename T> inline static long  AddrToRelAddr(T CmdAddr, UINT CmdLen, T TgtAddr){return -((CmdAddr + CmdLen) - TgtAddr);}
template<typename T> inline static T     RelAddrToAddr(T CmdAddr, UINT CmdLen, long TgtOffset){return ((CmdAddr + CmdLen) + TgtOffset);}
//------------------------------------------------------------------------------------------------------------
template<typename T> bool IsAddrInRange(T Addr, PBYTE BegPtr, PBYTE EndPtr)
{
 return (((PBYTE)Addr >= BegPtr) && ((PBYTE)Addr < EndPtr)); 
}
//------------------------------------------------------------------------------------------------------------
// pfnClient table is not changing between versions
//
template<typename T> bool IsPfnClientTbl(T* Addr, PBYTE BegPtr, PBYTE EndPtr)  // Passing DWORD as T assumes native x32
{
 static const int pfnClientCount = 23;   // Win7

 T pDefWindowProc = Addr[1];
 if(!IsAddrInRange(pDefWindowProc, BegPtr, EndPtr))return false;
 if(Addr[4]  != pDefWindowProc)return false;
 if(Addr[5]  != pDefWindowProc)return false;
 if(Addr[6]  != pDefWindowProc)return false;
 if(Addr[16] != pDefWindowProc)return false;

 if(Addr[0]  == pDefWindowProc)return false;
 if(Addr[2]  == pDefWindowProc)return false;
 if(Addr[3]  == pDefWindowProc)return false;
 if(Addr[7]  == pDefWindowProc)return false;
 if(Addr[8]  == pDefWindowProc)return false;
 if(Addr[9]  == pDefWindowProc)return false;
 if(Addr[10] == pDefWindowProc)return false;
 if(Addr[11] == pDefWindowProc)return false;
 if(Addr[12] == pDefWindowProc)return false;
 if(Addr[13] == pDefWindowProc)return false;
 if(Addr[14] == pDefWindowProc)return false;
 if(Addr[15] == pDefWindowProc)return false;
 if(Addr[17] == pDefWindowProc)return false;
 if(Addr[18] == pDefWindowProc)return false;
 if(Addr[19] == pDefWindowProc)return false;
 if(Addr[20] == pDefWindowProc)return false;
 if(Addr[21] == pDefWindowProc)return false;
 if(Addr[22] == pDefWindowProc)return false;

 for(int idx=0;idx < pfnClientCount;idx++)
  {
   if(!IsAddrInRange(Addr[idx], BegPtr, EndPtr))return false;
  }
 return true;
}
//------------------------------------------------------------------------------------------------------------
template<typename T, int ApfnMinCount> bool FindRangedTblBase(PBYTE BegPtr, PBYTE EndPtr, PBYTE ModBegPtr, PBYTE ModEndPtr, ULONG* ApfnEntriesNum, PVOID* pApfnTable, PVOID* pClientA, PVOID* pClientB)
{
 PBYTE CurPtr     = BegPtr;
 PVOID LastBase   = NULL;
 for(int MatchCtr=0;CurPtr < EndPtr;CurPtr += sizeof(T))
  {
   if(*pApfnTable && *pClientA && *pClientB)return false;
   if(!*pApfnTable)
    {
     PBYTE Addr = PBYTE(*(T*)CurPtr);
     if(IsAddrInRange(Addr, ModBegPtr, ModEndPtr))   //       (Addr >= BegPtr) && (Addr < EndPtr))
      {
       if(!MatchCtr)LastBase = CurPtr;
       MatchCtr++;       
      }
       else
        {
         if(MatchCtr > ApfnMinCount)
          {
           if(ApfnEntriesNum)*ApfnEntriesNum = MatchCtr;
           *pApfnTable = LastBase;
           continue;
          }
         MatchCtr = 0;
        }
    }
   if(!*pClientA || !*pClientB)   // pfnClientA or pfnClientW
    {
#ifdef KERNELDRV
     bool IsNativeX32 = (sizeof(void*) == 4) && (sizeof(T) == 4);    // Same as the driver
#else
     bool IsNativeX32 = !(sizeof(void*) == 8) && !IsWow64Sys();
#endif     
     bool found = IsNativeX32?IsPfnClientTbl((UINT32*)CurPtr, ModBegPtr, ModEndPtr):IsPfnClientTbl((UINT64*)CurPtr, ModBegPtr, ModEndPtr); 
     if(found) 
      {
       if(!*pClientA)*pClientA = CurPtr;
         else *pClientB = CurPtr;
      }
    }
  }
 return true;
}
//------------------------------------------------------------------------------------------------------------
// Independant of current architecture
// It is the only big table of functions pointing inside User32
PVOID _stdcall FindUser32Tables(PVOID pUser32, ULONG* ApfnEntriesNum, PVOID* pClientA, PVOID* pClientB)
{
 static const int ApfnMinCount = 99;
 if(!IsValidPEHeader(pUser32))return NULL;
 SECTION_HEADER Sec;
 SIZE_T ModuleSize = GetSizeOfImagePE(pUser32);
 PVOID ApfnTable = NULL;
 *pClientA = *pClientB = NULL;
 *ApfnEntriesNum = 0;
 PBYTE ModBegPtr = (PBYTE)pUser32;
 PBYTE ModEndPtr = &ModBegPtr[ModuleSize];
 for(UINT Idx=0;!GetModuleSectionByIdx(pUser32, Idx, &Sec);Idx++)    // Not all memory segments have committed memory but it is safe to skan any defined PE section
  {
   PBYTE BegPtr = (PBYTE)pUser32 + Sec.SectionRva;
   PBYTE EndPtr = BegPtr + Sec.PhysicalSize;
   bool res;
   DBGMSG("Section: BegPtr=%p, EndPtr=%p",BegPtr,EndPtr);
   if(IsValidModuleX64(pUser32))res = FindRangedTblBase<UINT64, ApfnMinCount>(BegPtr, EndPtr, ModBegPtr, ModEndPtr, ApfnEntriesNum, &ApfnTable, pClientA, pClientB);
     else res = FindRangedTblBase<UINT32, ApfnMinCount>(BegPtr, EndPtr, ModBegPtr, ModEndPtr, ApfnEntriesNum, &ApfnTable, pClientA, pClientB);
   if(!res)return ApfnTable;  // All tables found
  }
 return NULL;
}
//------------------------------------------------------------------------------------------------------------
// Finds 'call LoadLibraryExW' inside ClientLoadLibrary (6 bytes on x32 and x64: FF 15 NN NN NN NN)
//
PVOID _stdcall GetLLPtrIfClientLL(PVOID ProcAddr, PVOID LLImpEntry, bool IsX64)
{
 static const int MaxProcSize = 200;
 PBYTE BegPtr = (PBYTE)ProcAddr;
 PBYTE EndPtr = &BegPtr[MaxProcSize];
 PBYTE CurPtr = BegPtr;
 for(;CurPtr < EndPtr;CurPtr++)
  {
   if((CurPtr[0] != 0xFF)||(CurPtr[1] != 0x15))continue;
   PVOID Addr;
   if(IsX64)Addr = RelAddrToAddr(CurPtr,6,*(long*)&CurPtr[2]);
     else Addr = PVOID(*(UINT32*)&CurPtr[2]);
   if(Addr == LLImpEntry)return CurPtr;     // Found: call LoadLibraryExW
  }
 return NULL;
}
//------------------------------------------------------------------------------------------------------------
template<typename T> PVOID FindClientLLInApfn(PVOID ApfnTable, ULONG ApfnNum, PVOID LLEntry, PVOID* pClientLL=NULL)
{
 for(UINT ctr=0;ctr < ApfnNum;ctr++)
  {    
   PVOID PAddr = (PVOID)((T*)ApfnTable)[ctr];    
   PVOID res = GetLLPtrIfClientLL(PAddr, LLEntry, (sizeof(T) == 8));
   if(!res)continue;
   if(pClientLL)*pClientLL = PAddr;
   return res;
  }
 return NULL;
}
//------------------------------------------------------------------------------------------------------------
// Import table must be already resolved
PVOID _stdcall FindClientLoadLibraryCallLL(PVOID pUser32, PVOID ApfnTable, ULONG ApfnNum, PVOID* pClientLL=NULL)
{
 if(!IsValidPEHeader(pUser32))return NULL;
 PVOID EntryA = NULL; 
 PVOID EntryB = NULL;   // <<< May point to UINT64 or UINT32 which does not matter
 if(OIGetEntryPointersForApiName(NULL, "LoadLibraryExW", pUser32, &EntryA, &EntryB))return NULL;
 if(IsValidModuleX64(pUser32))return FindClientLLInApfn<UINT64>(ApfnTable, ApfnNum, EntryB, pClientLL);
 return FindClientLLInApfn<UINT32>(ApfnTable, ApfnNum, EntryB, pClientLL);
}
//------------------------------------------------------------------------------------------------------------
// The patch will persist between the driver reloads because there is no Copy-On-Write with IoAllocateMdl
static bool _stdcall IsUser32AlreadyPatched(PBYTE pFreeTxt, bool IsX54)
{
 if(IsX54)     
  {
   if(*(UINT64*)pFreeTxt == (UINT64)&pFreeTxt[8])return true;
  }
   else
    {
     if(*(UINT32*)pFreeTxt == (UINT32)&pFreeTxt[4])return true;
    }
 return false;
}
//------------------------------------------------------------------------------------------------------------
PVOID _stdcall PreparePatchRegion(PBYTE* Base, SIZE_T* Size)
{
#ifdef KERNELDRV
 if(PMDL Mdl = IoAllocateMdl(*Base, *Size, FALSE, FALSE, NULL))
  {
   DBGMSG("Mdl: %p",Mdl);
 __try
  {
   MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);        // Will fail for a protected process (i.e. sppsvc.exe)
   if(PBYTE MappBase = (PBYTE)MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority))
    {
     DBGMSG("Mapping: %p",MappBase);
     NTSTATUS stat = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
     if(stat >= 0)
      {
       *Base = MappBase;
       DBGMSG("MappBase=%p, MDL=%p", MappBase, Mdl);
       return Mdl; 
      }
       else {DBGMSG("(MmProtectMdlSystemAddress) Failure!");}
     DBGMSG("Releasing...", MappBase);
     MmUnmapLockedPages(MappBase, Mdl);
    }
      else {DBGMSG("(MmMapLockedPagesSpecifyCache) Failure!");}
   MmUnlockPages(Mdl);
  }__except(EXCEPTION_EXECUTE_HANDLER)
    {       
     DBGMSG("(MmProbeAndLockPages) Failure: %08X!", GetExceptionCode());
    }
   IoFreeMdl(Mdl);
  }
   else {DBGMSG("(IoAllocateMdl) Failure!");}
#else
 if(!pZwProtectVirtualMemory)
  {
   *(PVOID*)&pZwProtectVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwProtectVirtualMemory");
   if(!pZwProtectVirtualMemory){DBGMSG("Failed to find ZwProtectVirtualMemory!"); return 0;}
  }
 ULONG OldProtect;
 if(pZwProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), (PVOID*)Base, Size, PAGE_EXECUTE_READWRITE, &OldProtect) >= 0)return (PVOID)OldProtect; 
#endif
 return NULL;
}
//------------------------------------------------------------------------------------------------------------
void _stdcall ReleasePatchRegion(PBYTE Address, SIZE_T Size, PVOID Handle)
{                
 DBGMSG("Releasing: Address=%p, Handle=%p", Address, Handle);
#ifdef KERNELDRV
 MmUnmapLockedPages(Address, (PMDL)Handle);
 MmUnlockPages((PMDL)Handle);
 IoFreeMdl((PMDL)Handle);
#else
 ULONG OldProtect   = (ULONG)Handle;
 PVOID  BaseAddress = Address;
 SIZE_T RegionSize  = Size;
 if(pZwProtectVirtualMemory)pZwProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), &BaseAddress, &RegionSize, OldProtect, &OldProtect);
#endif
}
//------------------------------------------------------------------------------------------------------------
UINT _stdcall CalcProcBeginSize(PBYTE Addr, UINT MinReqLen, bool IsX64)
{
 UINT Len = 0;
 if(IsX64)
  {
   NHDE::HDE64 dhde;
   for(;Len < MinReqLen;Addr += dhde.len)Len += dhde.Disasm(Addr);
  }
   else
    {
     NHDE::HDE32 dhde;
     for(;Len < MinReqLen;Addr += dhde.len)Len += dhde.Disasm(Addr);
    }
 return Len;
}
//------------------------------------------------------------------------------------------------------------
// pFreeTxt relates to PatchBuf
UINT _stdcall InitStubDispWHook(PBYTE PatchBuf, UINT PBOffset, PBYTE pFreeTxt, PBYTE pDispatchHook, PBYTE DispHookStub, UINT StubLen, UINT BHOffs, long* pJmpRel, bool IsX64User32)
{
 static const ULONG MaxBadHookAdr = 0x00800000;  // 8mb

 UINT OrigCodeLenA = CalcProcBeginSize(pDispatchHook, 5, IsX64User32);    // 5 for a simple rel jump in range of User32
 memcpy(&PatchBuf[PBOffset], DispHookStub, StubLen);
 *(UINT32*)&PatchBuf[PBOffset+BHOffs] = MaxBadHookAdr;
 memcpy(&PatchBuf[PBOffset+StubLen], pDispatchHook, OrigCodeLenA);
 UINT JmpOffs = PBOffset+StubLen+OrigCodeLenA;
 PatchBuf[JmpOffs] = 0xE9;  // Jmp Rel32
 *(long*)&PatchBuf[JmpOffs+1] = AddrToRelAddr(&pFreeTxt[JmpOffs], 5, &pDispatchHook[OrigCodeLenA]);
 *pJmpRel = AddrToRelAddr(pDispatchHook, 5, &pFreeTxt[PBOffset]);
 return JmpOffs + 5;
}
//------------------------------------------------------------------------------------------------------------
ULONG _stdcall PreparePatches(PBYTE PatchBuf, PBYTE pFreeTxt, PVOID pCallLL, PBYTE pDispatchHookA, PBYTE pDispatchHookB, PBYTE pCallNxtHook, INT32* Value, long* pJmpRelA, long* pJmpRelB, bool IsX64User32)
{
 ULONG PatchSize = 0;
 if(IsX64User32)
  {
   static BYTE LLExStub64[] = {0x48, 0x8B, 0x04, 0x24, 0x50, 0x50, 0x50, 0x48, 0x89, 0x44, 0x24, 0x20, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x75, 0x03, 0x48, 0xFF, 0xC8, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x5A, 0x5A, 0x5A, 0x48, 0x89, 0x0C, 0x24, 0xC3};
   static BYTE CallNxtHook64[]  = {0x4D, 0x8B, 0xC8, 0x4C, 0x8B, 0xC2, 0x48, 0x8B, 0xD1, 0x48, 0x33, 0xC9, 0xE9, 0,0,0,0};
   static BYTE DispHookStub64[] = {0x48, 0x33, 0xC0, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x3B, 0xC8, 0x77, 0x0A, 0x49, 0xB9, 0,0,0,0,0,0,0,0};
   static const int CodeOffsA = 8;
   static const int CodeOffsB = 47;
   static const int RvaOffs64 = 22;
   ULONG CurOffs = 0;

   PVOID LLAddr = RelAddrToAddr((PBYTE)pCallLL, 6, *Value);   // Addr of LoadLibraryExW import  
   *Value = AddrToRelAddr((PBYTE)pCallLL, 6, pFreeTxt);  // RVA 

   *(UINT64*)&PatchBuf[CurOffs] = (UINT64)&pFreeTxt[CodeOffsA];   // Fake Import Entry: Address of the stub
   CurOffs   = CodeOffsA;
   memcpy(&PatchBuf[CurOffs], &LLExStub64, sizeof(LLExStub64));
   CurOffs  += sizeof(LLExStub64);
   *(INT32*)&PatchBuf[RvaOffs64] = AddrToRelAddr(&pFreeTxt[RvaOffs64-2], 6, (PBYTE)LLAddr);   // Real LoadLibraryExW import  

   UINT64 AddrCNH = (UINT64)pFreeTxt + CurOffs;
   memcpy(&PatchBuf[CurOffs], &CallNxtHook64, sizeof(CallNxtHook64));
   *(long*)&PatchBuf[CurOffs + 13] = AddrToRelAddr((PBYTE)&pFreeTxt[CurOffs + 12], 5, pCallNxtHook);     
   CurOffs += sizeof(CallNxtHook64); 

   ULONG PrvOffs = CurOffs;
   CurOffs   = InitStubDispWHook(PatchBuf, CurOffs, pFreeTxt, pDispatchHookA, DispHookStub64, sizeof(DispHookStub64), 4, pJmpRelA, IsX64User32); 
   *(UINT64*)&PatchBuf[PrvOffs+sizeof(DispHookStub64)-8] = AddrCNH;
   PrvOffs   = CurOffs;   
   PatchSize = InitStubDispWHook(PatchBuf, CurOffs, pFreeTxt, pDispatchHookB, DispHookStub64, sizeof(DispHookStub64), 4, pJmpRelB, IsX64User32);
   *(UINT64*)&PatchBuf[PrvOffs+sizeof(DispHookStub64)-8] = AddrCNH;
  }
   else 
    {
     static BYTE LLExStub32[] = {0x58, 0x59, 0x5A, 0x5A, 0x50, 0x52, 0x6A, 0x00, 0x51, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x01, 0x48, 0xC3};
     static BYTE CallNxtHook32[]  = {0x58, 0x6A, 0x00, 0x50, 0xE9, 0,0,0,0};
     static BYTE DispHookStub32[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x44, 0x24, 0x10, 0x7E, 0x09, 0x3E, 0xC7, 0x44, 0x24, 0x10, 0,0,0,0};
     static const int CodeOffsA = 4;
     static const int CodeOffsB = 25;
     static const int RvaOffs32 = 15;
     ULONG CurOffs = 0;

     *(UINT32*)&PatchBuf[CurOffs] = (UINT32)&pFreeTxt[CodeOffsA];   // Fake Import Entry: Address of the stub
     CurOffs   = CodeOffsA;
     memcpy(&PatchBuf[CurOffs], &LLExStub32, sizeof(LLExStub32));
     CurOffs  += sizeof(LLExStub32);
     *(INT32*)&PatchBuf[RvaOffs32] = *Value;   // Real LoadLibraryExW import 
     *Value    = (UINT32)pFreeTxt;    // Address     // Relocs???

     UINT32 AddrCNH = (UINT32)pFreeTxt + CurOffs;
     memcpy(&PatchBuf[CurOffs], &CallNxtHook32, sizeof(CallNxtHook32));
     *(long*)&PatchBuf[CurOffs + 5] = AddrToRelAddr((PBYTE)&pFreeTxt[CurOffs + 4], 5, pCallNxtHook);     
     CurOffs += sizeof(CallNxtHook32);    

     ULONG PrvOffs = CurOffs;
     CurOffs   = InitStubDispWHook(PatchBuf, CurOffs, pFreeTxt, pDispatchHookA, DispHookStub32, sizeof(DispHookStub32), 1, pJmpRelA, IsX64User32);   
     *(UINT32*)&PatchBuf[PrvOffs+sizeof(DispHookStub32)-4] = AddrCNH;
     PrvOffs = CurOffs;
     PatchSize = InitStubDispWHook(PatchBuf, CurOffs, pFreeTxt, pDispatchHookB, DispHookStub32, sizeof(DispHookStub32), 1, pJmpRelB, IsX64User32);
     *(UINT32*)&PatchBuf[PrvOffs+sizeof(DispHookStub32)-4] = AddrCNH;
    } 
 return PatchSize;
}
//------------------------------------------------------------------------------------------------------------
/* // x32:
 NNNNNNNN       StubProc      // ClientLoadLibrary::LoadLibraryExW import
StubProc:
 58             pop eax       // Ret Addr                                      
 59             pop ecx       // pLibFileName                                       
 5A             pop edx       // hFile (unused)                                      
 5A             pop edx       // dwFlags                                      
 50             push eax                                            
 52             push edx                                            
 6A 00          push 0                                              
 51             push ecx                                            
 FF15 XXXXXXXX  call dword ptr [XXXXXXXX]    // Real LoadLibraryExW import                    
 85C0           test eax,eax                                        
 75 01          jne lblEnd                                 
 48             dec eax  
lblEnd:                                           
 C3             ret                                                 
*/
/* // x64:
  NNNNNNNNNNNNNNNN      StubProc      // ClientLoadLibrary::LoadLibraryExW import
StubProc:
 48:8B0424      mov rax,qword ptr [rsp]        // Ret Addr                   
 50             push rax                       // Keep the stack aligned to 16               
 50             push rax                                       
 50             push rax                                       
 48:894424 20   mov qword ptr [rsp+20],rax                  
 FF15 XXXXXXXX  call qword ptr [XXXXXXXX]               
 48:85C0        test rax,rax                                   
 75 03          jne lblEnd                        
 48:FFC8        dec rax 
lblEnd:                                         
 48:8B4C24 20   mov rcx,qword ptr [rsp+20]                  
 5A             pop rdx                                        
 5A             pop rdx                                        
 5A             pop rdx                                        
 48:890C24      mov qword ptr [rsp],rcx                     
 C3             ret                                                                                                  
*/

/*
 48:33C0       xor rax,rax                                                                         
 B8 00000000   mov eax,0                                                                           
 4C:3BC8       cmp r9,rax                                                                          
 77 02         ja lblOrig                                                            
 C3            ret 
lblOrig:                                                                                
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 90            nop                                                                                 
 E9 00000000   jmp ContinueOrig                                                            
*/

/*  Windows 10 20H2:
// C0000098 STATUS_FILE_INVALID == 03EE ERROR_FILE_INVALID    // With STATUS_ACCESS_DENIED NtOpenFile will be called twice 
 
mov     eax, large fs:18h
mov     [eax+34h], 1655

mov     rax, gs:30h
mov     [rax+68h], 1655 
*/

/*  Windows 10:
      MiAddSecureEntry ( MmSecureVirtualMemory )
        PsCallImageNotifyRoutines
      MmUnsecureVirtualMemory
*/
// Makes LoadLibraryExW return -1 instead of NULL for ClientLoadLibrary
//
int _stdcall PatchUser32(PVOID pUser32)
{
 static const int DispatchHookIdx = 19;     // Not changing for now

 static ULONG PCallRVA32 = 0;
 static ULONG TFreeRVA32 = 0;
 static ULONG TFreeLen32 = 0;
 static ULONG CallNxtHookkRva32  = 0;
 static ULONG DispatchHookRva32A = 0;
 static ULONG DispatchHookRva32B = 0;

 static ULONG PCallRVA64 = 0;
 static ULONG TFreeRVA64 = 0;
 static ULONG TFreeLen64 = 0;
 static ULONG CallNxtHookkRva64  = 0;
 static ULONG DispatchHookRva64A = 0;
 static ULONG DispatchHookRva64B = 0;

 if(!pUser32){DBGMSG("pUser32 is NULL!"); return -1;}
#ifdef KERNELDRV
 static const bool IsThisCodeX64 = (sizeof(void*) == 8);
#else
 bool IsThisCodeX64 = (sizeof(void*) == 8) || IsWow64Sys();
#endif
 SECTION_HEADER shdr;
 bool IsX64User32 = IsValidModuleX64(pUser32);
 PVOID pCallLL  = 0;
 PBYTE pFreeTxt = NULL;
 PBYTE pTxtBase = NULL;
 PBYTE pCallNxtHook   = NULL;
 PBYTE pDispatchHookA = NULL;
 PBYTE pDispatchHookB = NULL;
 long  TxtSize  = NULL;
 long  FreeSize = 0;
 if((IsX64User32 && !PCallRVA64) || (!IsX64User32 && !PCallRVA32))
  {
   DBGMSG("Scanning User32(X64: %u): %p", (int)IsX64User32, pUser32); 
   if(GetModuleSection(pUser32, ".text", &shdr)){DBGMSG("Failed to find Text section!"); return -2;}
   pTxtBase = (PBYTE)pUser32 + shdr.SectionRva;
   pFreeTxt = pTxtBase + shdr.PhysicalSize;
   TxtSize  = shdr.VirtualSize;
   FreeSize = ((shdr.VirtualSize + 0x1000) & ~0xFFF) - shdr.PhysicalSize;   // VirtualSize may be specified smaller than RawSize
   if(FreeSize <= 0){DBGMSG("No free space!"); return -3;}
   if(IsUser32AlreadyPatched(pFreeTxt, IsX64User32)){DBGMSG("User32(X64: %u) is still patched globally!", (int)IsX64User32); return -8;}
   PVOID pCNH = OIGetProcAddress(pUser32, "CallNextHookEx");
   if(!pCNH){DBGMSG("Failed to find CallNextHookEx!"); return -10;}

   ULONG NumCnt   = 0;
   PVOID pClntLL  = NULL;
   PVOID pClientA = NULL; 
   PVOID pClientB = NULL; 
   PVOID ApfnTbl  = FindUser32Tables(pUser32, &NumCnt, &pClientA, &pClientB);
   if(!ApfnTbl){DBGMSG("Failed to find APFN table!"); return -4;}
   pCallLL = FindClientLoadLibraryCallLL(pUser32, ApfnTbl, NumCnt, &pClntLL);
   if(!pCallLL){DBGMSG("Failed to find ClientLoadDll!"); return -5;}
   if(IsX64User32)
    {
     CallNxtHookkRva64 = (PBYTE)pCNH - (PBYTE)pUser32;
     PCallRVA64 = (PBYTE)pCallLL  - (PBYTE)pUser32;
     TFreeRVA64 = (PBYTE)pFreeTxt - (PBYTE)pUser32;
     TFreeLen64 = FreeSize;
     DispatchHookRva64A = ((UINT64*)pClientA)[DispatchHookIdx] - (SIZE_T)pUser32;
     DispatchHookRva64B = ((UINT64*)pClientB)[DispatchHookIdx] - (SIZE_T)pUser32;
     pDispatchHookA = (PBYTE)pUser32 + DispatchHookRva64A;
     pDispatchHookB = (PBYTE)pUser32 + DispatchHookRva64B;
     pCallNxtHook   = (PBYTE)pUser32 + CallNxtHookkRva64;
    }
     else
      {
       CallNxtHookkRva32 = (PBYTE)pCNH - (PBYTE)pUser32;
       PCallRVA32 = (PBYTE)pCallLL  - (PBYTE)pUser32;
       TFreeRVA32 = (PBYTE)pFreeTxt - (PBYTE)pUser32;
       TFreeLen32 = FreeSize;
       if(IsThisCodeX64)  // WOW64 User32
        {
         DispatchHookRva32A = ((UINT64*)pClientA)[DispatchHookIdx] - (SIZE_T)pUser32;
         DispatchHookRva32B = ((UINT64*)pClientB)[DispatchHookIdx] - (SIZE_T)pUser32;
        }
         else
          {
           DispatchHookRva32A = ((UINT32*)pClientA)[DispatchHookIdx] - (SIZE_T)pUser32;
           DispatchHookRva32B = ((UINT32*)pClientB)[DispatchHookIdx] - (SIZE_T)pUser32;
          }
       pDispatchHookA = (PBYTE)pUser32 + DispatchHookRva32A;
       pDispatchHookB = (PBYTE)pUser32 + DispatchHookRva32B;
       pCallNxtHook   = (PBYTE)pUser32 + CallNxtHookkRva32;
      }
   DBGMSG("Using found values."); 
  }
   else    // Use cashed values
    {
     if(IsX64User32)
      {
       pCallLL  = (PBYTE)pUser32 + PCallRVA64;
       pFreeTxt = (PBYTE)pUser32 + TFreeRVA64;
       FreeSize = TFreeLen64;
       pDispatchHookA = (PBYTE)pUser32 + DispatchHookRva64A;
       pDispatchHookB = (PBYTE)pUser32 + DispatchHookRva64B;
       pCallNxtHook   = (PBYTE)pUser32 + CallNxtHookkRva64;
      }
       else
        {
         pCallLL  = (PBYTE)pUser32 + PCallRVA32;
         pFreeTxt = (PBYTE)pUser32 + TFreeRVA32;
         FreeSize = TFreeLen32;
         pDispatchHookA = (PBYTE)pUser32 + DispatchHookRva32A;
         pDispatchHookB = (PBYTE)pUser32 + DispatchHookRva32B;
         pCallNxtHook   = (PBYTE)pUser32 + CallNxtHookkRva32;
        }
     DBGMSG("Using cached values."); 
     if(IsUser32AlreadyPatched(pFreeTxt, IsX64User32)){DBGMSG("User32(X64: %u) is still patched globally!", (int)IsX64User32); return -8;}
    }
 DBGMSG("pCallLL=%p, pDispatchHookA=%p, pDispatchHookB=%p, pFreeTxt=%p, FreeSize=%u",pCallLL,pDispatchHookA,pDispatchHookB,pFreeTxt,FreeSize);

 BYTE  PatchBuf[256];
 PBYTE ValPtr  = &((PBYTE)pCallLL)[2];
 INT32 Value   = *(INT32*)ValPtr;    // Old value of 'call [xxxx]'
 long  JmpRelA = 0; 
 long  JmpRelB = 0;
 ULONG PatchSize = PreparePatches(PatchBuf, pFreeTxt, pCallLL, pDispatchHookA, pDispatchHookB, pCallNxtHook, &Value, &JmpRelA, &JmpRelB, IsX64User32);
 if(FreeSize < PatchSize){DBGMSG("Not enough free space!"); return -6;}

 DBGMSG("pTxtBase=%p, TxtSize=%08X",pTxtBase,TxtSize);
 PBYTE  Base = pTxtBase;
 SIZE_T Size = TxtSize;
 if(PVOID Hndl = PreparePatchRegion(&Base, &Size))
  {
   DBGMSG("Patching...");
   memcpy(&Base[pFreeTxt - pTxtBase], &PatchBuf, PatchSize);

   *(INT32*)&Base[ValPtr - pTxtBase] = Value;    // Call to LoadLibraryEx from ClientLoadLibrary   //  *(INT32*)&Base[(ValPtr - (PBYTE)pUser32) - (pTxtBase - (PBYTE)pUser32)]

   BYTE TmpBuf[8];                // _InterlockedCompareExchange64
   PBYTE JmpPtr = &Base[pDispatchHookA - pTxtBase];
   memcpy(&TmpBuf, JmpPtr, sizeof(TmpBuf));
   *TmpBuf = 0xE9;
   *(long*)&TmpBuf[1] = JmpRelA;
   _InterlockedCompareExchange64((long long *)JmpPtr, *(long long *)&TmpBuf, *(long long *)JmpPtr); 

   JmpPtr = &Base[pDispatchHookB - pTxtBase];
   memcpy(&TmpBuf, JmpPtr, sizeof(TmpBuf));
   *TmpBuf = 0xE9;
   *(long*)&TmpBuf[1] = JmpRelB;
   _InterlockedCompareExchange64((long long *)JmpPtr, *(long long *)&TmpBuf, *(long long *)JmpPtr); 
  
   DBGMSG("Patched at %p", pCallLL);
   ReleasePatchRegion(Base, Size, Hndl);
  }
   else {DBGMSG("PreparePatchRegion failed!");}
 DBGMSG("Done");
 return 0;  
}
//------------------------------------------------------------------------------------------------------------
