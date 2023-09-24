#include <Windows.h>
#include "PEedit.hpp"

extern "C" // c++������c����Ҫ����
{
	#include <Psapi.h>	
	#include "gpacktype.h"
}

#ifndef _GPACK_H
#define _GPACK_H

typedef struct _GPACK_TMPBUF_ENTRY
{
	LPBYTE PackedBuf;
	DWORD  DpackSize;
	DWORD  OrgRva;//������Ϊ0������ӵ����һ�����Σ���ѹ��
	DWORD  OrgMemSize;
	DWORD  Characteristics;
}GPACK_TMPBUF_ENTRY, * PGPACK_TMPBUF_ENTRY; // ���һ����shellcode

class CGpack
{
public:
	static LPBYTE zstdPack(LPBYTE pSrcBuf, size_t srcSize,
		size_t* pDstSize, double maxmul = 2.0); // �ӿ�ѹ���㷨
	static LPBYTE zstdUnpack(LPBYTE pSrcBuf, size_t srcSize); // ��ѹ�㷨

private:
	char m_strFilePath[MAX_PATH];

protected:
	CPEedit m_packpe; // ��Ҫ�ӿǵ�exe pe�ṹ
	CPEedit m_shellpe; // �ǵ�pe�ṹ
	PGPACK_SHELL_INDEX m_pShellIndex; // dll�еĵ����ṹ
	HMODULE m_hShell; // ��dll�ľ��

	WORD m_gpackSectNum;
	GPACK_TMPBUF_ENTRY m_gpackTmpbuf[MAX_GPACKSECTNUM]; // �ӿ���������
	bool m_packSectMap[MAX_GPACKSECTNUM]; // �����Ƿ�ѹ��map

	WORD initGpackTmpbuf();//����ԭ��dpackTmpBuf����
	WORD addGpackTmpbufEntry(LPBYTE packBuf, DWORD packBufSize,
		DWORD srcRva = 0, DWORD OrgMemSize = 0, DWORD Characteristics = 0xE0000000);//����dpack����
	DWORD packSection(int type = GPACK_SECTION_DLZMA);	//pack������

	DWORD loadShellDll(const char* dllpath);	//�������, return dll size
	void initShellIndex(DWORD shellEndRva); // ��ʼ��ȫ�ֱ���
	DWORD adjustShellReloc(DWORD shellBaseRva);// ����dll�ض�λ��Ϣ�����ظ���
	DWORD adjustShellIat(DWORD shellBaseRva);// ������ƫ����ɵ�dll iat����
	DWORD makeAppendBuf(DWORD shellStartRva, DWORD shellEndRva, DWORD shellBaseRva); // ׼������shellcode��buf
	void adjustPackpeHeaders(DWORD offset); // ��������shellcode���peͷ��Ϣ

public:
	CGpack()
	{
		iniValue();
	}
	CGpack(char* path);
	virtual ~CGpack()
	{
		release();
	}
	void iniValue();
	virtual	void release();

	DWORD loadPeFile(const char* path); //����pe�ļ�������isPE()ֵ
	DWORD packPe(const char* dllpath, int type = GPACK_SECTION_DLZMA); // �ӿǣ�ʧ�ܷ���0���ɹ�����pack���ݴ�С
	DWORD unpackPe(int type = 0); // �ѿǣ�����ͬ�ϣ���ʱ��ʵ�֣�
	DWORD savePe(const char* path); // ʧ�ܷ���0���ɹ������ļ���С
	const char* getFilePath() const;
	CPEinfo* getExepe();
};
#endif