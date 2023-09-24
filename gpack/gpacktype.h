#include <Windows.h>
#ifndef _GPACKPROC_H
#define _GPACKPROC_H
#define MAX_GPACKSECTNUM 16 // 最多可pack区段数量
#define GPACK_SECTION_RAW 0
#define GPACK_SECTION_DLZMA 1

typedef struct _ZSTD_HEADER
{
	size_t RawDataSize;  // 原始数据的大小
	size_t CompressedSize;  // 压缩后的数据的大小
} ZSTD_HEADER, * PZSTD_HEADER;

typedef struct _GPACK_ORGPE_INDEX   //源程序被隐去的信息，此结构为明文表示，地址全是rva
{
#ifdef _WIN64
	ULONGLONG ImageBase;			//源程序基址
#else
	DWORD ImageBase;			//源程序基址
#endif
	DWORD OepRva;				//原程序rva入口
	DWORD ImportRva;			//导入表信息
	DWORD ImportSize;
}GPACK_ORGPE_INDEX, * PGPACK_ORGPE_INDEX;

typedef struct _GPACK_SECTION_ENTRY //源信息与压缩变换后信息索引表是
{
	//假设不超过4g
	DWORD OrgRva; // OrgRva为0时则是不解压到原来区段
	DWORD OrgSize;
	DWORD GpackRva;
	DWORD GpackSize;
	DWORD Characteristics;
	DWORD GpackSectionType; // GPACK区段类型
}GPACK_SECTION_ENTRY, * PGPACK_SECTION_ENTRY;

typedef struct _GPACK_SHELL_INDEX//GPACK变换头
{
	union
	{
		PVOID GpackOepFunc;  // 初始化壳的入口函数（放第一个元素方便初始化）
		DWORD GpackOepRva;  // 加载shellcode后也许改成入口RVA
	};
	GPACK_ORGPE_INDEX OrgIndex;
	WORD SectionNum;									//变换的区段数，最多MAX_GPACKSECTNUM区段
	GPACK_SECTION_ENTRY SectionIndex[MAX_GPACKSECTNUM];		//变换区段索引, 以全0结尾
	PVOID Extra;									//其他信息，方便之后拓展
}GPACK_SHELL_INDEX, * PGPACK_SHELL_INDEX;

size_t zstdPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);
size_t zstdUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);

#endif