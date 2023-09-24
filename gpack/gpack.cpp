#define _CRT_SECURE_NO_WARNINGS
#include "gpack.hpp"
#include <iostream>

LPBYTE CGpack::zstdPack(LPBYTE pSrcBuf, size_t srcSize, size_t* pDstSize, double maxmul)
{
	if (pSrcBuf == NULL) return 0;
	LPBYTE pDstBuf = NULL;
	size_t dstSize = 0;

	for (double m = 1; m <= maxmul; m += 0.1)
	{
		pDstBuf = new BYTE[(size_t)(m * (double)srcSize)
			+ sizeof(ZSTD_HEADER)]; //防止分配缓存区空间过小
		dstSize = ::zstdPack(pDstBuf, pSrcBuf, srcSize); // 此处要特别注意，缓存区尺寸
		if (dstSize > 0) break;
		delete[] pDstBuf;
	}
	if (pDstSize != NULL) *pDstSize = dstSize;
	if (dstSize == 0)
	{
		delete[] pDstBuf;
		pDstBuf = NULL;
	}
	return pDstBuf;
}

LPBYTE CGpack::zstdUnpack(LPBYTE pSrcBuf, size_t srcSize)
{
	if (pSrcBuf == NULL) return 0;
	LPBYTE pDstBuf = NULL;
	auto pZstdHeader = (PZSTD_HEADER)(pSrcBuf);
	size_t dstSize = pZstdHeader->RawDataSize;
	pDstBuf = new BYTE[dstSize]; //防止分配缓存区空间过小
	::zstdUnpack(pDstBuf, pSrcBuf, srcSize); // 此处要特别注意，缓存区尺寸
	return pDstBuf;
}

void CGpack::iniValue()
{
	memset(m_strFilePath, 0, MAX_PATH);
	memset(m_packSectMap, 0, sizeof(m_packSectMap));
	m_hShell = NULL;
	m_pShellIndex = NULL;
	m_gpackSectNum = 0;
}

CGpack::CGpack(char* path)
{
	iniValue();
	loadPeFile(path);
}

void CGpack::release()
{
	initGpackTmpbuf();
	m_packpe.closePeFile();
	m_shellpe.closePeFile();
	if (m_hShell != NULL) FreeLibrary((HMODULE)m_hShell);
}

WORD CGpack::initGpackTmpbuf()
{
	WORD oldDpackSectNum = m_gpackSectNum;
	if (m_gpackSectNum != 0)
	{
		for (int i = 0; i < m_gpackSectNum; i++)
			if (m_gpackTmpbuf[i].PackedBuf != NULL && m_gpackTmpbuf[i].DpackSize != 0)
				delete[] m_gpackTmpbuf[i].PackedBuf;
	}
	m_gpackSectNum = 0;
	memset(m_gpackTmpbuf, 0, sizeof(m_gpackTmpbuf));
	return oldDpackSectNum;
}

WORD CGpack::addGpackTmpbufEntry(LPBYTE packBuf, DWORD packBufSize,
	DWORD srcRva, DWORD OrgMemSize, DWORD Characteristics)
{
	m_gpackTmpbuf[m_gpackSectNum].PackedBuf = packBuf;
	m_gpackTmpbuf[m_gpackSectNum].DpackSize = packBufSize;
	m_gpackTmpbuf[m_gpackSectNum].OrgRva = srcRva;
	m_gpackTmpbuf[m_gpackSectNum].OrgMemSize = OrgMemSize;
	m_gpackTmpbuf[m_gpackSectNum].Characteristics = Characteristics;
	m_gpackSectNum++;
	return m_gpackSectNum;
}

DWORD CGpack::packSection(int dpackSectionType)	//处理各区段
{
	switch (dpackSectionType)
	{
	case GPACK_SECTION_RAW:
	{
		break;
	}
	case GPACK_SECTION_DLZMA:
	{
		DWORD allsize = 0;
		WORD sectNum = m_packpe.getSectionNum();
		auto pSectHeader = m_packpe.getSectionHeader();

		// 确定要压缩的区段
		int sectIdx = -1;
		for (int i = 0; i < sectNum; i++)
		{
			m_packSectMap[i] = true;
		}

		// rsrc
		sectIdx = m_packpe.findRvaSectIdx(
			m_packpe.getImageDataDirectory()
			[IMAGE_DIRECTORY_ENTRY_RESOURCE]
			.VirtualAddress);
		if (sectIdx != -1)
		{
			m_packSectMap[sectIdx] = false;
		}

		// security
		sectIdx = m_packpe.findRvaSectIdx(
			m_packpe.getImageDataDirectory()
			[IMAGE_DIRECTORY_ENTRY_SECURITY]
			.VirtualAddress);
		if (sectIdx != -1)
		{
			m_packSectMap[sectIdx] = false;
		}

		// tls
		sectIdx = m_packpe.findRvaSectIdx(
			m_packpe.getImageDataDirectory()
			[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if (sectIdx != -1)
		{
			m_packSectMap[sectIdx] = false;
		}

		// exception
		sectIdx = m_packpe.findRvaSectIdx(
			m_packpe.getImageDataDirectory()
			[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
			.VirtualAddress);
		if (sectIdx != -1)
		{
			m_packSectMap[sectIdx] = false;
		}

		//pack各区段
		m_gpackSectNum = 0;
		for (int i = 0; i < sectNum; i++)
		{
			if (m_packSectMap[i] == false)
			{
				continue;
			}
			DWORD sectStartOffset =
				m_packpe.isMemAlign() ?
				pSectHeader[i].VirtualAddress :
				pSectHeader[i].PointerToRawData;
			LPBYTE pSrcBuf = m_packpe.getPeBuf()
				+ sectStartOffset;//指向缓存区
			DWORD srcSize = // 压缩大小
				pSectHeader[i].Misc.VirtualSize;
			size_t packedSize = 0;
			LPBYTE pPackedtBuf = zstdPack( // 压缩区段
				pSrcBuf, srcSize, &packedSize);
			if (packedSize == 0)
			{
				std::cout <<
					"error: dlzmaPack failed in section "
					<< i << std::endl;
				return 0;
			}
			addGpackTmpbufEntry(
				pPackedtBuf,
				(DWORD)(packedSize + // 注意加上头
					sizeof(ZSTD_HEADER)),
				pSectHeader[i].VirtualAddress,
				pSectHeader[i].Misc.VirtualSize,
				pSectHeader[i].Characteristics);
			allsize += (DWORD)packedSize;
		}
		return allsize;
	}
	default:
	{
		break;
	}
	}
	return 0;
}

//处理外壳,若其他操作系统要重写
DWORD CGpack::loadShellDll(const char* dllpath)
{
	m_hShell = LoadLibraryA(dllpath);
#ifndef _WIN64
	printf("simpledpackshell.dll load at %08X\n",
		(unsigned int)m_hShell);
#else
	printf("simpledpachshell64.dll load at %016lX\n",
		(unsigned long)m_hShell);
#endif
	MODULEINFO meminfo = { 0 };//读取dpack shell 代码
	GetModuleInformation(GetCurrentProcess(),
		m_hShell, &meminfo, sizeof(MODULEINFO));
	m_shellpe.attachPeBuf((LPBYTE)m_hShell,
		meminfo.SizeOfImage, true); // 复制到新缓存区，防止virtual protect无法修改
	m_pShellIndex = (PGPACK_SHELL_INDEX)(
		m_shellpe.getPeBuf() +
		(size_t)GetProcAddress(m_hShell,
			"g_dpackShellIndex") - (size_t)m_hShell);
	return meminfo.SizeOfImage;
}

DWORD CGpack::adjustShellReloc(DWORD shellBaseRva)//设置dll重定位信息，返回个数
{
	size_t oldImageBase = m_hShell ? (size_t)m_hShell :
		m_shellpe.getOptionalHeader()->ImageBase;
	return m_shellpe.shiftReloc(oldImageBase,
		m_packpe.getOptionalHeader()->ImageBase,
		shellBaseRva);
}

DWORD CGpack::adjustShellIat(DWORD shellBaseRva) // 调整shellcode中的iat
{
	return m_shellpe.shiftOft(shellBaseRva);
}

void CGpack::initShellIndex(DWORD shellEndRva)
{
	//g_dpackShellIndex OrgIndex赋值
	m_pShellIndex->OrgIndex.OepRva = m_packpe.getOepRva();
	m_pShellIndex->OrgIndex.ImageBase =
		m_packpe.getOptionalHeader()->ImageBase;
	auto pPackpeImpEntry = &m_packpe.
		getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	m_pShellIndex->OrgIndex.ImportRva =
		pPackpeImpEntry->VirtualAddress;
	m_pShellIndex->OrgIndex.ImportSize =
		pPackpeImpEntry->Size;

	//g_dpackShellIndex  SectionIndex赋值
	DWORD trva = m_packpe.getOptionalHeader()->SizeOfImage + shellEndRva;
	for (int i = 0; i < m_gpackSectNum; i++) //将压缩区段信息存取shell
	{
		m_pShellIndex->SectionIndex[i].OrgRva =
			m_gpackTmpbuf[i].OrgRva;
		m_pShellIndex->SectionIndex[i].OrgSize =
			m_gpackTmpbuf[i].OrgMemSize;
		m_pShellIndex->SectionIndex[i].GpackRva = trva;
		m_pShellIndex->SectionIndex[i].GpackSize =
			m_gpackTmpbuf[i].DpackSize;
		m_pShellIndex->SectionIndex[i].GpackSectionType =
			GPACK_SECTION_DLZMA;
		m_pShellIndex->SectionIndex[i].Characteristics =
			m_gpackTmpbuf[i].Characteristics;
		trva += m_gpackTmpbuf[i].DpackSize;
	}
	m_pShellIndex->SectionNum = m_gpackSectNum;
}

DWORD CGpack::makeAppendBuf(DWORD shellStartRva, DWORD shellEndRva, DWORD shellBaseRva)
{
	DWORD bufsize = shellEndRva - shellStartRva;
	LPBYTE pBuf = new BYTE[bufsize];
	memcpy(pBuf, m_shellpe.getPeBuf() + shellStartRva, bufsize);

#if 1
	// 清空export表,  可能会报毒
	auto pExpDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		(size_t)m_shellpe.getExportDirectory()
		- (size_t)m_shellpe.getPeBuf() + (size_t)pBuf - shellStartRva);
	LPBYTE pbtmp = pBuf + pExpDirectory->Name - shellStartRva;
	while (*pbtmp != 0) *pbtmp++ = 0;
	DWORD n = pExpDirectory->NumberOfFunctions;
	PDWORD  pdwtmp = (PDWORD)(pBuf + pExpDirectory->AddressOfFunctions - shellStartRva);
	for (unsigned int i = 0; i < n; i++) *pdwtmp++ = 0;
	n = pExpDirectory->NumberOfNames;
	pdwtmp = (PDWORD)(pBuf + pExpDirectory->AddressOfNames - shellStartRva);
	for (unsigned int i = 0; i < n; i++)
	{
		pbtmp = *pdwtmp - shellStartRva + pBuf;
		while (*pbtmp != 0) *pbtmp++ = 0;
		*pdwtmp++ = 0;
	}
	memset(pExpDirectory, 0, sizeof(IMAGE_EXPORT_DIRECTORY));
#endif

	// 将改好的dll shell放入tmp buf
	addGpackTmpbufEntry(pBuf, bufsize, shellBaseRva + shellStartRva, bufsize);
	return shellStartRva;
}

void CGpack::adjustPackpeHeaders(DWORD offset)
{
	// 设置被加壳程序的信息, oep, reloc, iat
	if (m_pShellIndex == NULL) return;
	auto packpeImageSize = m_packpe.
		getOptionalHeader()->SizeOfImage;
	// m_pShellIndex->DpackOepFunc 之前已经reloc过了，变成了正确的va了(shelldll是release版)
	m_packpe.setOepRva((DWORD)(
		(size_t)m_pShellIndex->GpackOepFunc -
		m_packpe.getOptionalHeader()->ImageBase +
		offset));
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + packpeImageSize + offset,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].Size };
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IAT] = {
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + packpeImageSize + offset,
		m_shellpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_IAT].Size };
	m_packpe.getImageDataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0,0 };

	// pe 属性设置
	m_packpe.getFileHeader()->Characteristics |= IMAGE_FILE_RELOCS_STRIPPED; //禁止基址随机化
}

DWORD CGpack::loadPeFile(const char* path)//加载pe文件，返回isPE()值
{
	DWORD res = m_packpe.openPeFile(path);
	return res;
}

DWORD CGpack::packPe(const char* dllpath, int dpackSectionType)//加壳，失败返回0，成功返回pack数据大小
{
	if (m_packpe.getPeBuf() == NULL) return 0;
	initGpackTmpbuf(); // 初始化pack buf
	DWORD packsize = packSection(dpackSectionType); // pack各区段
	DWORD shellsize = loadShellDll(dllpath); // 载入dll shellcode

	DWORD packpeImgSize = m_packpe.getOptionalHeader()->SizeOfImage;
	DWORD shellStartRva = m_shellpe.getSectionHeader()[0].VirtualAddress;
	DWORD shellEndtRva = m_shellpe.getSectionHeader()[3].VirtualAddress; // rsrc

	adjustShellReloc(packpeImgSize); // reloc调整后全局变量g_dpackShellIndex的oep也变成之后
	adjustShellIat(packpeImgSize);
	initShellIndex(shellEndtRva); // 初始化dpack shell index，一定要在reloc之后, 因为reloc后这里的地址也变了
	makeAppendBuf(shellStartRva, shellEndtRva, packpeImgSize);
	adjustPackpeHeaders(0);   // 调整要pack的pe头
	return packsize + shellEndtRva - shellStartRva;
}

DWORD CGpack::unpackPe(int type)//脱壳，其他同上（暂时不实现）
{
	return 0;
}

DWORD CGpack::savePe(const char* path)//失败返回0，成功返回文件大小
{
	/*
		pack区域放到后面，由于内存有对齐问题，只允许pack一整个区段
		先改pe头，再分配空间，支持若原来pe fileHeader段不够，添加段
		将区段头与区段分开考虑
	*/
	// dpack头初始化
	IMAGE_SECTION_HEADER dpackSect = { 0 };
	strcpy((char*)dpackSect.Name, ".gc");
	dpackSect.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	dpackSect.VirtualAddress = m_gpackTmpbuf[m_gpackSectNum - 1].OrgRva;

	// 准备dpack buf
	DWORD dpackBufSize = 0;
	for (int i = 0; i < m_gpackSectNum; i++) dpackBufSize += m_gpackTmpbuf[i].DpackSize;
	LPBYTE pdpackBuf = new BYTE[dpackBufSize];
	LPBYTE pCurBuf = pdpackBuf;
	memcpy(pdpackBuf, m_gpackTmpbuf[m_gpackSectNum - 1].PackedBuf,
		m_gpackTmpbuf[m_gpackSectNum - 1].DpackSize); // 壳代码
	pCurBuf += m_gpackTmpbuf[m_gpackSectNum - 1].DpackSize;
	for (int i = 0; i < m_gpackSectNum - 1; i++)
	{
		memcpy(pCurBuf, m_gpackTmpbuf[i].PackedBuf,
			m_gpackTmpbuf[i].DpackSize); // 壳代码
		pCurBuf += m_gpackTmpbuf[i].DpackSize;
	}

	// 删除被压缩区段和写入pe
	int remvoeSectIdx[MAX_GPACKSECTNUM] = { 0 };
	int removeSectNum = 0;
	for (int i = 0; i < m_packpe.getFileHeader()->NumberOfSections; i++)
	{
		if (m_packSectMap[i] == true) remvoeSectIdx[removeSectNum++] = i;
	}
	m_packpe.removeSectionDatas(removeSectNum, remvoeSectIdx);
	m_packpe.appendSection(dpackSect, pdpackBuf, dpackBufSize);
	delete[] pdpackBuf;
	return m_packpe.savePeFile(path);
}

CPEinfo* CGpack::getExepe()
{
	return &m_packpe;
}

const char* CGpack::getFilePath() const
{
	return m_strFilePath;
}