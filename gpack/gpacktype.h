#include <Windows.h>
#ifndef _GPACKPROC_H
#define _GPACKPROC_H
#define MAX_GPACKSECTNUM 16 // ����pack��������
#define GPACK_SECTION_RAW 0
#define GPACK_SECTION_DLZMA 1

typedef struct _ZSTD_HEADER
{
	size_t RawDataSize;  // ԭʼ���ݵĴ�С
	size_t CompressedSize;  // ѹ��������ݵĴ�С
} ZSTD_HEADER, * PZSTD_HEADER;

typedef struct _GPACK_ORGPE_INDEX   //Դ������ȥ����Ϣ���˽ṹΪ���ı�ʾ����ַȫ��rva
{
#ifdef _WIN64
	ULONGLONG ImageBase;			//Դ�����ַ
#else
	DWORD ImageBase;			//Դ�����ַ
#endif
	DWORD OepRva;				//ԭ����rva���
	DWORD ImportRva;			//�������Ϣ
	DWORD ImportSize;
}GPACK_ORGPE_INDEX, * PGPACK_ORGPE_INDEX;

typedef struct _GPACK_SECTION_ENTRY //Դ��Ϣ��ѹ���任����Ϣ��������
{
	//���費����4g
	DWORD OrgRva; // OrgRvaΪ0ʱ���ǲ���ѹ��ԭ������
	DWORD OrgSize;
	DWORD GpackRva;
	DWORD GpackSize;
	DWORD Characteristics;
	DWORD GpackSectionType; // GPACK��������
}GPACK_SECTION_ENTRY, * PGPACK_SECTION_ENTRY;

typedef struct _GPACK_SHELL_INDEX//GPACK�任ͷ
{
	union
	{
		PVOID GpackOepFunc;  // ��ʼ���ǵ���ں������ŵ�һ��Ԫ�ط����ʼ����
		DWORD GpackOepRva;  // ����shellcode��Ҳ��ĳ����RVA
	};
	GPACK_ORGPE_INDEX OrgIndex;
	WORD SectionNum;									//�任�������������MAX_GPACKSECTNUM����
	GPACK_SECTION_ENTRY SectionIndex[MAX_GPACKSECTNUM];		//�任��������, ��ȫ0��β
	PVOID Extra;									//������Ϣ������֮����չ
}GPACK_SHELL_INDEX, * PGPACK_SHELL_INDEX;

size_t zstdPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);
size_t zstdUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize);

#endif