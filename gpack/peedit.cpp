#include "PEedit.hpp"
#include <fstream>
using namespace std;

/* static functions */
DWORD CPEedit::addOverlay(const char* path, LPBYTE pOverlay, DWORD size)//附加数据，此处不再对齐了
{
	if (pOverlay == NULL) return 0;
	ofstream fout(path, ios::binary | ios::app);
	if (fout.fail()) return 0;
	fout.seekp(0, ios::end);
	fout.write((const char*)pOverlay, size);
	fout.close();
	return size;
}

DWORD CPEedit::setOepRva(const char* path, DWORD rva)
{
	BYTE buf[PEHBUF_SIZE];
	int readsize = readFile(path, buf, PEHBUF_SIZE);
	if (readsize == 0) return 0;
	DWORD oldrva = setOepRva((LPBYTE)buf, rva);
	if (oldrva == 0) return 0;
	ofstream fout(path, ios::binary | ios::ate | ios::in);//ios::out则清空文件，ios::app每次写都是在最后，ios::ate可以用seekp
	fout.seekp(0, ios::beg);
	fout.write((const char*)buf, readsize);
	fout.close();
	return oldrva;
}

DWORD CPEedit::setOepRva(LPBYTE pPeBuf, DWORD rva)//返回原来的rva
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	DWORD* pRva = &getOptionalHeader(pPeBuf)->AddressOfEntryPoint;
	DWORD oldrva = *pRva;
	*pRva = rva;
	return oldrva;
}

DWORD CPEedit::shiftReloc(LPBYTE pPeBuf, size_t oldImageBase,
	size_t newImageBase, DWORD offset, bool bMemAlign)
{
	//修复重定位,其实此处pShellBuf为hShell副本
	DWORD all_num = 0;
	DWORD sumsize = 0;
	auto pRelocEntry = &getImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	while (sumsize < pRelocEntry->Size)
	{
		auto pBaseRelocation = (PIMAGE_BASE_RELOCATION)(pPeBuf
			+ sumsize + (bMemAlign ?
				pRelocEntry->VirtualAddress : rva2faddr(
					pPeBuf, pRelocEntry->VirtualAddress)));
		auto pRelocOffset = (PRELOCOFFSET)
			((LPBYTE)pBaseRelocation +
				sizeof(IMAGE_BASE_RELOCATION));
		DWORD item_num = (pBaseRelocation->SizeOfBlock -
			sizeof(IMAGE_BASE_RELOCATION)) /
			sizeof(RELOCOFFSET);
		for (size_t i = 0; i < item_num; i++)
		{
			if (!pRelocOffset[i].type && !pRelocOffset[i].offset)
			{
				continue;
			}
			DWORD toffset = pRelocOffset[i].offset +
				pBaseRelocation->VirtualAddress;
			if (!bMemAlign) toffset =
				rva2faddr(pPeBuf, toffset);

			// 新的重定位地址 = 重定位后的地址(VA)-加载时的镜像基址(hModule VA) + 新的镜像基址(VA) + 新代码基址RVA（前面用于存放压缩的代码）
			// 由于讲dll附加在后面，需要在dll shell中的重定位加上偏移修正
#ifdef _WIN64
			* (PULONGLONG)(pPeBuf + toffset) += //重定向每一项地址
				newImageBase - oldImageBase + offset;
#else
			//printf("reloc at rva %08X, ", toffset);
			//printf("%08X -> ", *(PDWORD)(pPeBuf + toffset));
			* (PDWORD)(pPeBuf + toffset) += //重定向每一项地址
				newImageBase - oldImageBase + offset;
			//printf("%08X\n", *(PDWORD)(pPeBuf + toffset));
#endif
		}
		pBaseRelocation->VirtualAddress += offset; //重定向页表基址
		sumsize += sizeof(RELOCOFFSET) * item_num +
			sizeof(IMAGE_BASE_RELOCATION);
		all_num += item_num;
	}
	return all_num;
}

DWORD CPEedit::shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign, bool bResetFt)
{
	auto pImportEntry = &getImageDataDirectory(pPeBuf)[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD dll_num = pImportEntry->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD func_num = 0;//所有导入函数个数，不包括全0的项
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuf +
		(bMemAlign ? pImportEntry->VirtualAddress :
			rva2faddr(pPeBuf, pImportEntry->VirtualAddress)));//指向第一个dll
	for (size_t i = 0; i < dll_num; i++)
	{
		if (pImportDescriptor[i].OriginalFirstThunk == 0) continue;
		auto pOFT = (PIMAGE_THUNK_DATA)(pPeBuf + (bMemAlign ?
			pImportDescriptor[i].OriginalFirstThunk :
			rva2faddr(pPeBuf, pImportDescriptor[i].OriginalFirstThunk)));
		auto pFT = (PIMAGE_THUNK_DATA)(pPeBuf + (bMemAlign ?
			pImportDescriptor[i].FirstThunk :
			rva2faddr(pPeBuf, pImportDescriptor[i].FirstThunk)));
		DWORD item_num = 0;
		for (int j = 0; pOFT[j].u1.AddressOfData != 0; j++)
		{
			item_num++; //一个dll中导入函数的个数,不包括全0的项
			if ((pOFT[j].u1.Ordinal >> 31) != 0x1) //不是用序号
			{
				pOFT[j].u1.AddressOfData += offset;
				if (bResetFt) pFT[j].u1.AddressOfData = pOFT[j].u1.AddressOfData;
			}
		}
		pImportDescriptor[i].OriginalFirstThunk += offset;
		pImportDescriptor[i].FirstThunk += offset;
		pImportDescriptor[i].Name += offset;
		func_num += item_num;
	}
	return func_num;
}

DWORD CPEedit::appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,
	LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign)
{
	WORD oldSectNum = getFileHeader(pPeBuf)->NumberOfSections++;
	auto pOptHeader = getOptionalHeader(pPeBuf);
	auto pSectHeader = getSectionHeader(pPeBuf);
	DWORD fileAlign = pOptHeader->FileAlignment;
	DWORD memAlign = pOptHeader->SectionAlignment;

	// 修正新sect header指针
	if (!newSectHeader.SizeOfRawData)
	{
		newSectHeader.SizeOfRawData = toAlign(newSectSize, fileAlign);
	}
	if (!newSectHeader.Misc.VirtualSize)
	{
		newSectHeader.Misc.VirtualSize = newSectSize;
	}
	if (!newSectHeader.PointerToRawData)
	{
		newSectHeader.PointerToRawData = toAlign(
			pSectHeader[oldSectNum - 1].PointerToRawData
			+ pSectHeader[oldSectNum - 1].SizeOfRawData, fileAlign);
	}
	else
	{
		if (newSectHeader.PointerToRawData < pSectHeader[oldSectNum - 1].PointerToRawData
			+ toAlign(pSectHeader[oldSectNum - 1].PointerToRawData, fileAlign))
		{
			return 0; // 指定faddr 比原来最后一个区段小，无法添加
		}
	}
	if (!newSectHeader.VirtualAddress) // 不指定rva
	{
		newSectHeader.VirtualAddress = toAlign(
			pSectHeader[oldSectNum - 1].VirtualAddress
			+ pSectHeader[oldSectNum - 1].SizeOfRawData, memAlign);
	}
	else
	{
		if (newSectHeader.VirtualAddress < pSectHeader[oldSectNum - 1].VirtualAddress
			+ toAlign(pSectHeader[oldSectNum - 1].Misc.VirtualSize, memAlign))
		{
			return 0; // 指定rva 比原来最后一个区段小，无法添加
		}
		// 修改前一个区段VitrualSize使得内存上没有空隙
		pSectHeader[oldSectNum - 1].Misc.VirtualSize +=
			(newSectHeader.VirtualAddress -
				pSectHeader[oldSectNum - 1].VirtualAddress -
				pSectHeader[oldSectNum - 1].Misc.VirtualSize) / memAlign * memAlign;
	}

	// 添加新区段头
	memcpy(&pSectHeader[oldSectNum], &newSectHeader, sizeof(IMAGE_SECTION_HEADER));
	memset(&pSectHeader[oldSectNum + 1], 0, sizeof(IMAGE_SECTION_HEADER));

	// 添加新区段数据
	LPBYTE pNewSectStart = pPeBuf + (bMemAlign ?
		pSectHeader[oldSectNum].VirtualAddress : pSectHeader->PointerToRawData);
	memset(pNewSectStart, 0, bMemAlign ? memAlign : fileAlign);
	memcpy(pNewSectStart, pNewSectBuf, newSectSize);

	// 修正pe大小
	//pOptHeader->SizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);
	pOptHeader->SizeOfImage = pSectHeader[oldSectNum].VirtualAddress
		+ toAlign(pSectHeader[oldSectNum].Misc.VirtualSize, memAlign);
	return bMemAlign ? toAlign(newSectSize, memAlign) :
		toAlign(newSectSize, fileAlign);
}

DWORD CPEedit::removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[])
{
	WORD oldSectNum = getFileHeader(pPeBuf)->NumberOfSections;
	auto pOptHeader = getOptionalHeader(pPeBuf);
	auto pSectHeader = getSectionHeader(pPeBuf);
	DWORD decreseRawSize = 0;

	for (int i = 0; i < removeNum; i++) // 排序
	{
		for (int j = i + 1; j < removeNum; j++)
		{
			if (removeIdx[j] < removeIdx[i])
			{
				int tmp = removeIdx[j];
				removeIdx[j] = removeIdx[i];
				removeIdx[i] = tmp;
			}
		}
	}
	int tmpidx = removeIdx[0];
	int j = 0;
	for (int i = 0; i < oldSectNum; i++)
	{
		if (tmpidx > removeNum - 1 || i < removeIdx[tmpidx]) continue; // 保留的区段
		//移除的区段
		decreseRawSize += pSectHeader[i].SizeOfRawData;
		pSectHeader[i].SizeOfRawData = 0;
		if (i < oldSectNum - 1)
			pSectHeader[i + 1].PointerToRawData = pSectHeader[i].PointerToRawData;
		tmpidx++;
	}
	return decreseRawSize;
}

DWORD CPEedit::savePeFile(const char* path,
	LPBYTE pPeBuf, DWORD FileBufSize,
	bool bMemAlign, bool bShrinkPe,
	LPBYTE pOverlayBuf, DWORD OverlayBufSize)//失败返回0，成功返回写入总字节数
{
	if (pPeBuf == NULL) return 0;
	fstream fout;
	fout.open(path, ios::out | ios::binary);
	if (isPe((LPBYTE)pPeBuf) < 0) return 0;

	//写入pe头
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pPeBuf);
	PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pPeBuf);
	fout.write((const char*)pPeBuf, pOptionalHeader->SizeOfHeaders);
	DWORD writesize = pOptionalHeader->SizeOfHeaders;

	// 写入各区段
	for (int i = 0; i < getFileHeader(pPeBuf)->NumberOfSections; i++)
	{
		DWORD sectOffset = bMemAlign ?
			pSecHeader[i].VirtualAddress : pSecHeader[i].PointerToRawData;
		DWORD sectsize = toAlign(pSecHeader[i].SizeOfRawData, pOptionalHeader->FileAlignment);

		auto cur = fout.tellp();//防止地址不对
		if (cur > pSecHeader[i].PointerToRawData) //防止重叠
		{
			fout.seekp(pSecHeader[i].PointerToRawData);
		}
		else if (cur < pSecHeader[i].PointerToRawData) //防止区段少
		{
			if (bShrinkPe)
			{
				pSecHeader[i].PointerToRawData = (DWORD)cur;
			}
			else
			{
				for (std::streamoff j = cur; j < pSecHeader[i].PointerToRawData; j++) fout.put(0);
			}
		}
		fout.write((const char*)(pPeBuf + sectOffset), sectsize);
		writesize += sectsize;
	}

	// 写入附加段
	if (pOverlayBuf != NULL && OverlayBufSize != 0)
	{
		fout.write((const char*)pOverlayBuf, OverlayBufSize);
		writesize += OverlayBufSize;
	}

	//重新写入修正的PE头
	fout.seekp(0, ios::beg);
	fout.write((const char*)pPeBuf, pOptionalHeader->SizeOfHeaders);
	fout.close();
	return writesize;
}
/* static functions end */

/* public funcitons*/
DWORD CPEedit::setOepRva(DWORD rva)
{
	return setOepRva(m_pPeBuf, rva);
}

DWORD  CPEedit::shiftReloc(size_t oldImageBase, size_t newImageBase, DWORD offset)
{
	return shiftReloc(m_pPeBuf, oldImageBase, newImageBase, offset, m_bMemAlign);
}

DWORD  CPEedit::shiftOft(DWORD offset, bool bResetFt)
{
	return shiftOft(m_pPeBuf, offset, m_bMemAlign, bResetFt);
}

DWORD CPEedit::appendSection(IMAGE_SECTION_HEADER newSectHeader, LPBYTE pSectBuf, DWORD newSectSize)
{
	DWORD addedSize = toAlign(newSectSize), newBufSize = 0;
	if (m_bMemAlign)
	{
		newBufSize = (newSectHeader.VirtualAddress > m_dwPeBufSize ?
			newSectHeader.VirtualAddress : m_dwPeBufSize) + addedSize;
	}
	else
	{

		newBufSize = (newSectHeader.PointerToRawData > m_dwPeBufSize ?
			newSectHeader.PointerToRawData : m_dwPeBufSize) + addedSize;
	}

	LPBYTE pTmp = new BYTE[newBufSize];
	memset(pTmp, 0, newBufSize);
	memcpy(pTmp, m_pPeBuf, m_dwPeBufSize);
	if (m_bMemAlloc) delete[] m_pPeBuf;
	m_bMemAlloc = true;
	m_pPeBuf = pTmp;
	m_dwPeBufSize = newBufSize;
	return appendSection(m_pPeBuf, newSectHeader, pSectBuf, newSectSize, m_bMemAlign);
}

DWORD CPEedit::removeSectionDatas(int removeNum, int removeIdx[])
{
	return removeSectionDatas(m_pPeBuf, removeNum, removeIdx);
}

DWORD CPEedit::savePeFile(const char* path, bool bShrinkPe)
{
	return savePeFile(path, m_pPeBuf, m_dwPeBufSize,
		m_bMemAlign, bShrinkPe,
		m_pOverlayBuf, m_dwOverlayBufSize);
}

/* public funcitons end*/