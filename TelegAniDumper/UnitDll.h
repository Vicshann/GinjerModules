
#pragma once

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
 
#include "..\GlobalInjector\GInjer\LoaderCode.h"
#include "Crypto\MD5.hpp"
#include "GIF.hpp"

#define CFGSECNAME L"Parameters"

#define  MAXANI 32
//====================================================================================
#pragma pack(push,1)
struct SQImgData
{
 DWORD Unk01;  // 1
 DWORD Width;
 DWORD Height;
 DWORD PixelBits;  // 32 
 DWORD DataSize;
 DWORD Unk03;
 DWORD Unk04;
 DWORD Unk05;
 PVOID Unk06;
 PVOID PixelData;
 DWORD Unk07; // 6
 DWORD BytesPerRow;
};

struct SQImage
{
 PVOID VFT;
 PVOID UnkA;
 PVOID UnkB;
 SQImgData* ImageData;
};

#pragma pack(pop)

/*struct SAniDesc
{
 PVOID ChThis;
 PVOID FrmReq;
 int   TotalFrames;
 int   LastFrame;
};  */

struct SFrmSeq
{
 struct SFrmRec
  {
   SFrmRec* Next;
   UINT  Size;
   UINT8 Data[0];
  };

 PVOID This; 
 PVOID FrameReq;
 UINT  TotalFrames;
 UINT  FramesPrsent;
 UINT  FrameRate;
 UINT  PixelBits;
 UINT  Width;     // Must be same for all frames
 UINT  Height;    // Must be same for all frames
 DWORD AddTime;
 SFrmRec* FirstFrm;
 SFrmRec* LastFrm;
 DWORD FirstFrmHash[4];  // MD5

//---------------------------------------------------
void Clear(void)
 {
  for(SFrmRec* Rec=this->FirstFrm;Rec;)
   {
    SFrmRec* Next = Rec->Next;
    free(Rec);
    Rec = Next;
   }
  memset(this,0,sizeof(SFrmSeq));
 }
//---------------------------------------------------
void Add(PVOID Data, UINT Size)
{
 SFrmRec* Rec = (SFrmRec*)malloc(sizeof(SFrmRec) + Size);
 Rec->Next = NULL;
 Rec->Size = Size;
 memcpy(&Rec->Data, Data, Size);
 if(this->LastFrm)
  {
   this->LastFrm->Next = Rec;
   this->LastFrm = Rec; 
  }
   else this->LastFrm = this->FirstFrm = Rec;
 this->FramesPrsent++;
}
//---------------------------------------------------
};
//====================================================================================
void _stdcall LoadConfiguration(void);
bool _stdcall InitApplication(void);

bool _stdcall FindAndHookRenderFrame(void);
bool __fastcall Proc_Cache_renderFrame(PVOID This, PVOID UnusedEDX, SQImage* TgtQImage, PVOID FrameReq, int FrmIndex);
//====================================================================================
