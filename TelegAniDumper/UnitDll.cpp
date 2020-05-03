
/*
  Copyright (c) 2020 Victor Sheinmann, Vicshann@gmail.com

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
bool DumpGifs    = true;
bool DumpBitmaps = true;
bool GifDoDither      = false;
int  GifQuantLevel    = 5;
int  GifAlphaTreshold = 50; 
int  GifTranspColor   = 0x00FF00FF;
//---------------------------------------
PHOOK(Proc_Cache_renderFrame)HookRenderFrame;

// NtCurrentTeb()->LastErrorValue = SInjModDesc*  (Always fits into 32 bits, valid if > 65535)

SFrmSeq AniList[MAXANI];

wchar_t WorkFolder[MAX_PATH];
wchar_t CfgFilePath[MAX_PATH];  

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
      ExtPtr[-2] = 'd';    //Telegram.exd
      *ExtPtr = 0;
      lstrcpyW(GetFileExt(LogFilePath),L"log");
      lstrcpyW(GetFileExt(CfgFilePath),L"ini");
      LoadConfiguration();
      LOGMSG("Process path: %ls",&ProcPath);
      LOGMSG("WorkFolder: %ls, ExtPtr=%ls",&WorkFolder,ExtPtr);
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

 DumpGifs         = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"DumpGifs", DumpGifs, CfgFilePath); 
 DumpBitmaps      = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"DumpBitmaps", DumpBitmaps, CfgFilePath); 
 GifDoDither      = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"GifDoDither", GifDoDither, CfgFilePath); 
 GifQuantLevel    = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"GifQuantLevel", GifQuantLevel, CfgFilePath); 
 GifAlphaTreshold = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"GifAlphaTreshold", GifAlphaTreshold, CfgFilePath); 
 GifTranspColor   = INIRefreshValueInt<PWSTR>(CFGSECNAME, L"GifTranspColor", GifTranspColor, CfgFilePath);
 
 LOGMSG("Done");
}
//------------------------------------------------------------------------------------
bool _stdcall InitApplication(void)
{
 DBGMSG("Enter");
 FindAndHookRenderFrame();
 DBGMSG("Done");
 return true;
}
//====================================================================================

//------------------------------------------------------------------------------------
bool _stdcall FindAndHookRenderFrame(void)  
{
 NSIGP::CSigScan<> sig;
 ULONG MainExeSize = 0;
 PBYTE MainExeBase = (PBYTE)NNTDLL::GetModuleBaseLdr(NULL, &MainExeSize);

 WORD Sign[] = {0x5500, 0x8B00, 0xEC00, 0x8300, 0xE400, NSIGP::poSkp|(NSIGP::poSkp << 8), 0xEC00, NSIGP::poSkp|(NSIGP::poSkp << 8), 0x5600, 0x8B00, 0xF100, 0x5700, 0x8B00, 0x7D00, NSIGP::poSkp|(NSIGP::poSkp << 8), 0xBE00, NSIGP::poSkp|(NSIGP::poSkp << 8), 0x0000, 0x0000, 0x0F00, 0x8D00, NSIGP::poSkp|(NSIGP::poSkp << 8), 0x0000, 0x0000, 0x3B00, 0xBE00, NSIGP::poSkp|(NSIGP::poSkp << 8), 0x0000, 0x0000, 0x7400, NSIGP::poSkp|(NSIGP::poSkp << 8), 0xFF00, 0x0F00, 0x8500};     
 sig.AddSignature((PBYTE)&Sign, sizeof(Sign), NSIGP::sfBinary, 1, 1);  
 UINT Found  = sig.FindSignatures(&MainExeBase[4096], &MainExeBase[MainExeSize-4096], 1);
 if(!Found){DBGMSG("Signature not found"); return false;}
 PVOID Addr  = sig.GetSigAddr(0,0); 
 HookRenderFrame.SetHook(Addr);    // HookRenderFrame.SetHook(&MainExeBase[0x012F6980 - 0x00400000]);
 DBGMSG("Signature found: %p", Addr);
 return true;
}
//------------------------------------------------------------------------------------
int _stdcall SaveAsBitmap(PWSTR FilePath, UINT8* Data, UINT Size, UINT Width, UINT Height)
{
 HANDLE hBmpFile = CreateFileW(FilePath,GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
 if(hBmpFile == INVALID_HANDLE_VALUE){DBGMSG("Failed to create: %ls",FilePath); return -2;}

 DWORD Result;
 BITMAPFILEHEADER bfhdr;
 BITMAPINFO OutBmpInf;

 OutBmpInf.bmiHeader.biSize   = sizeof(BITMAPINFOHEADER);
 OutBmpInf.bmiHeader.biWidth  = Width;
 OutBmpInf.bmiHeader.biHeight = -Height; // Negative for Top-Bottom image
 OutBmpInf.bmiHeader.biPlanes = 1;
 OutBmpInf.bmiHeader.biBitCount = 32;  //DstQImage->ImageData->PixelBits;
 OutBmpInf.bmiHeader.biCompression = BI_RGB;   // RGBA
 OutBmpInf.bmiHeader.biSizeImage   = Size;  //DstQImage->ImageData->DataSize;          //RowSize * this->GetHeight();  

 OutBmpInf.bmiHeader.biXPelsPerMeter = 0;
 OutBmpInf.bmiHeader.biYPelsPerMeter = 0;
 OutBmpInf.bmiHeader.biClrUsed = 0;
 OutBmpInf.bmiHeader.biClrImportant = 0;

 bfhdr.bfType      = 0x4D42;  // 'BM'
 bfhdr.bfSize      = OutBmpInf.bmiHeader.biSizeImage + sizeof(BITMAPINFO) + sizeof(BITMAPFILEHEADER);
 bfhdr.bfOffBits   = sizeof(BITMAPINFO) + sizeof(BITMAPFILEHEADER);
 bfhdr.bfReserved1 = 0;
 bfhdr.bfReserved2 = 0;

 WriteFile(hBmpFile,&bfhdr,sizeof(BITMAPFILEHEADER),&Result,NULL);
 WriteFile(hBmpFile,&OutBmpInf,sizeof(BITMAPINFO),&Result,NULL);
 WriteFile(hBmpFile, Data, Size, &Result, NULL);
 CloseHandle(hBmpFile);
 DBGMSG("Saved: %ls",FilePath);
 return 0;
}
//------------------------------------------------------------------------------------
SFrmSeq* _stdcall AddAniRecFrame(PVOID ChThis, PVOID FrmReq, SQImage* SrcQImage, int FrameRate, int TotalFrames, int CurrFrame)
{
 SFrmSeq* ExistingRec = NULL;
 SFrmSeq* OldestRec = NULL;
 SFrmSeq* EmptyRec = NULL;
 DWORD LastTicks = -1; 
 for(UINT actr=0;actr < MAXANI;actr++)
  {
   SFrmSeq* ARec = &AniList[actr];
   if(!ARec->FrameReq){EmptyRec = ARec; continue;}
   if(ARec->AddTime < LastTicks){LastTicks = ARec->AddTime; OldestRec = ARec;}
   if((ARec->This == ChThis)&&(ARec->FrameReq == FrmReq)){ExistingRec = ARec; break;}
  }
 if(ExistingRec)    // Already exist
  {
   if(CurrFrame == 0)ExistingRec->Clear();  // Restart frame sequence
  }
 else if(EmptyRec)
  {
   if(CurrFrame != 0){DBGMSG("No sequence started yet!"); return NULL;}
   ExistingRec = EmptyRec;
  }
 else if(OldestRec)
  {
   if(CurrFrame == 0)OldestRec->Clear();  // Restart frame sequence
   ExistingRec = OldestRec;
  }
   else {DBGMSG("No slots available!"); return NULL;}
 if(CurrFrame == 0)
  {
   CMD5 md;
   DBGMSG("Initializing for: %p, %p",ChThis,FrmReq);
   ExistingRec->This         = ChThis;
   ExistingRec->FrameReq     = FrmReq;
   ExistingRec->FrameRate    = FrameRate;
   ExistingRec->TotalFrames  = TotalFrames;
   ExistingRec->FramesPrsent = 0;
   ExistingRec->PixelBits    = SrcQImage->ImageData->PixelBits;
   ExistingRec->Width   = SrcQImage->ImageData->Width;    
   ExistingRec->Height  = SrcQImage->ImageData->Height;   
   ExistingRec->AddTime = GetTickCount();
   UINT8* Hash = md.GetMD5((UINT8*)SrcQImage->ImageData->PixelData, SrcQImage->ImageData->DataSize);
   memcpy(ExistingRec->FirstFrmHash, Hash, 16);
   ExistingRec->FirstFrm = ExistingRec->LastFrm = NULL;
  }
   else
    {
     if((CurrFrame + 1) <= ExistingRec->FramesPrsent)
      {
       DBGMSG("Broken sequence!");
       ExistingRec->Clear();
       return NULL;
      }
    }
 DBGMSG("Adding frame for: %p, %p",ChThis,FrmReq);
 ExistingRec->Add(SrcQImage->ImageData->PixelData, SrcQImage->ImageData->DataSize);
 if(ExistingRec->FramesPrsent == ExistingRec->TotalFrames)   // Save frames and release entry
  {
   CGIF gif;
   wchar_t FilePath[MAX_PATH];
   int PathLen = wsprintfW(FilePath, L"%ls%08X%08X%08X%08X\\",&WorkFolder,ExistingRec->FirstFrmHash[0],ExistingRec->FirstFrmHash[1],ExistingRec->FirstFrmHash[2],ExistingRec->FirstFrmHash[3]);
   DBGMSG("Saving to '%ls'",&FilePath);
   int BmpCtr = 0;
   CreateDirectoryPath(FilePath);
   for(SFrmSeq::SFrmRec* Rec=ExistingRec->FirstFrm;Rec;Rec=Rec->Next)
    {
     if(DumpBitmaps)
      {
       wsprintfW(&FilePath[PathLen],L"%u.bmp",BmpCtr++);
       SaveAsBitmap(FilePath, (UINT8*)&Rec->Data, Rec->Size, ExistingRec->Width, ExistingRec->Height);
      }
     if(DumpGifs)
      {
       CGIF::CImgBlk* Img = gif.AddImage(ExistingRec->Width,ExistingRec->Height, 0, 0, GifTranspColor, GifAlphaTreshold, CGIF::FrmDelayFps(ExistingRec->FrameRate / 2), 2);
       if(Img)
        {
         UINT  PixSize = 0;
         PVOID Pixels  = Img->GetPixels(&PixSize);
         UINT Size = (PixSize < Rec->Size)?(PixSize):(Rec->Size); 
         memcpy(Pixels, &Rec->Data, Size);
        }
         else {DBGMSG("Failed to create GIF frame!");}
      }
    }
   if(DumpGifs)
    {
     gif.MakeGIF(0, GifDoDither, false, GifQuantLevel);
     lstrcpyW(&FilePath[PathLen], L"Animation.gif");  
     HANDLE hGifFile = CreateFileW(FilePath,GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
     if(hGifFile != INVALID_HANDLE_VALUE)
      {
       for(CGIF::SDataBlk* Blk=gif.BlkFirst();Blk;Blk=gif.BlkNext(Blk))   // Save all GIF parts
        {
         DWORD Result;        
         WriteFile(hGifFile,&Blk->Data,Blk->DataSize,&Result,NULL);
        }
       CloseHandle(hGifFile);
       DBGMSG("Saved: %ls",&FilePath);
      }
       else {DBGMSG("Failed to create: %ls",&FilePath);}
    }
   ExistingRec->Clear();
  }
 return 0;
}
//------------------------------------------------------------------------------------
bool __fastcall Proc_Cache_renderFrame(PVOID This, PVOID UnusedEDX, SQImage* DstQImage, PVOID FrameReq, int FrmIndex)
{
 DBGMSG("This=%p, UnusedEDX=%p, TgtQImage=%p, FrameReq=%p, FrmIndex=%u", This, UnusedEDX, DstQImage, FrameReq, FrmIndex);
 DWORD FrameRate   = *(PDWORD)((PBYTE)This + 0x9C);
 DWORD FramesReady = *(PDWORD)((PBYTE)This + 0xA0);
 DWORD FramesCount = *(PDWORD)((PBYTE)This + 0xA4);
 bool res = HookRenderFrame.OrigProc(This, UnusedEDX, DstQImage, FrameReq, FrmIndex);
 DBGMSG("Res=%u, FrameRate=%u, FramesReady=%u, FramesCount=%u", (int)res, FrameRate, FramesReady, FramesCount); 
 if(res && DstQImage->ImageData && DstQImage->ImageData->PixelData)AddAniRecFrame(This, FrameReq, DstQImage, FrameRate, FramesCount, FrmIndex);
 return res;
}
//------------------------------------------------------------------------------------

//====================================================================================
//                            HOOKED  WINAPI
//------------------------------------------------------------------------------------
//====================================================================================
