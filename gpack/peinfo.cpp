#define _CRT_SECURE_NO_WARNINGS
#include "PEinfo.hpp"
#include <fstream>
using namespace std;
/*Static*/
DWORD CPEinfo::getFileSize(const char* path)
{
	ifstream fin(path, ios::binary);
	if (fin.fail()) return 0;
	fin.seekg(0, ios::end);
	DWORD fsize = (DWORD)fin.tellg();
	fin.close();
	return fsize;
}

DWORD CPEinfo::readFile(const char* path, LPBYTE pFileBuf, DWORD size)//读文件，size为要读的数(0读取全部)，返回读取字节数，放到pFileBuf中
{
	if (pFileBuf == NULL) return 0;
	DWORD fsize;
	ifstream fin(path, ios::binary);
	if (fin.fail()) return 0;
	fin.seekg(0, ios::end);
	fsize = (DWORD)fin.tellg();
	fin.seekg(0, ios::beg);
	if (size == 0 || fsize < size)  size = fsize;
	fin.read((char*)pFileBuf, size);
	fin.close();
	return size;
}

DWORD CPEinfo::loadPeFile(const char* path,
	LPBYTE pPeBuf, DWORD* FileBufSize,
	bool bMemAlign,
	LPBYTE pOverlayBuf, DWORD* OverlayBufSize)//失败返回0，成功返回读取总字节数,FileBufSize=0自动确认
{
	if (pPeBuf == NULL) return 0;
	DWORD loadsize = 0;
	DWORD filesize = getFileSize(path);;
	LPBYTE buf = new BYTE[filesize];
	if (readFile(path, buf, 0) <= 0) return 0;
	if (isPe(buf) > 0)
	{
		PIMAGE_NT_HEADERS pNtHeader = getNtHeader(pPeBuf);
		PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pPeBuf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;
		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		DWORD last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		if (bMemAlign == false)
		{
			memcpy(pPeBuf, buf, filesize);
			if (FileBufSize != NULL) *FileBufSize = filesize;
			if (last_faddr < filesize)
			{
				memcpy(pOverlayBuf, buf + last_faddr, static_cast<size_t>(filesize) - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else
		{
			memset(pPeBuf, 0, memsize);
			loadsize = memsize;
			memcpy(pPeBuf, buf, pNtHeader->OptionalHeader.SizeOfHeaders);//PE区段
			for (int i = 0; i < sec_num; i++)//赋值
			{
				memcpy(pPeBuf + pSecHeader[i].VirtualAddress,
					buf + pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);
			}
			if (last_faddr < filesize)//附加数据
			{
				memcpy(pOverlayBuf, buf + last_faddr, static_cast<size_t>(filesize) - last_faddr);
				if (OverlayBufSize != NULL) *OverlayBufSize = filesize - last_faddr;
				loadsize += filesize - last_faddr;
			}
		}
		delete[] buf;
	}
	return loadsize;
}


int CPEinfo::isPe(const char* path)
{
	BYTE buf[PEHBUF_SIZE]{};//判断pe只读取前0x100字节就行
	if (readFile(path, (LPBYTE)buf, PEHBUF_SIZE) == 0)
		return -3;
	return isPe((LPBYTE)buf);
}

int CPEinfo::isPe(LPBYTE pPeBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return -1; //"MZ"
	PIMAGE_NT_HEADERS pNtHeader = getNtHeader(pPeBuf);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) return -2;  //"PE\0\0"
	return pNtHeader->OptionalHeader.Magic;
}

DWORD CPEinfo::toAlign(DWORD num, DWORD align)
{
	DWORD r = num % align;
	num -= r;
	if (r != 0) num += align;
	return num;
}

PIMAGE_NT_HEADERS CPEinfo::getNtHeader(LPBYTE pPeBuf)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPeBuf;
	return (PIMAGE_NT_HEADERS)(pPeBuf + pDosHeader->e_lfanew);
}

PIMAGE_FILE_HEADER CPEinfo::getFileHeader(LPBYTE pPeBuf)
{
	return &getNtHeader(pPeBuf)->FileHeader;
}

PIMAGE_OPTIONAL_HEADER CPEinfo::getOptionalHeader(LPBYTE pPeBuf)
{
	return &getNtHeader(pPeBuf)->OptionalHeader;
}

PIMAGE_DATA_DIRECTORY CPEinfo::getImageDataDirectory(LPBYTE pPeBuf)
{
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pPeBuf);
	return pOptionalHeader->DataDirectory;
}

PIMAGE_SECTION_HEADER CPEinfo::getSectionHeader(LPBYTE pPeBuf)
{
	PIMAGE_NT_HEADERS pNtHeader = getNtHeader(pPeBuf);
	return (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));
}

PIMAGE_IMPORT_DESCRIPTOR CPEinfo::getImportDescriptor(LPBYTE pPeBuf, bool bMemAlign = true)
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = getImageDataDirectory(pPeBuf);
	DWORD rva = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD offset = bMemAlign ? rva : rva2faddr(pPeBuf, rva);
	return (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuf + offset);
}

PIMAGE_EXPORT_DIRECTORY CPEinfo::getExportDirectory(LPBYTE pPeBuf, bool bMemAlign = true)
{
	PIMAGE_DATA_DIRECTORY pImageDataDirectory = getImageDataDirectory(pPeBuf);
	DWORD rva = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD offset = bMemAlign ? rva : rva2faddr(pPeBuf, rva);
	return (PIMAGE_EXPORT_DIRECTORY)(pPeBuf + offset);
}

DWORD CPEinfo::getOepRva(const char* path)
{
	BYTE buf[PEHBUF_SIZE];//判断pe只读取前0x100字节就行
	readFile(path, buf, PEHBUF_SIZE);
	return getOepRva(buf);
}

DWORD CPEinfo::getOepRva(LPBYTE pPeBuf)
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return getOptionalHeader(pPeBuf)->AddressOfEntryPoint;
}

WORD CPEinfo::getSectionNum(LPBYTE pPeBuf)
{
	return getFileHeader(pPeBuf)->NumberOfSections;
}

int CPEinfo::findRvaSectIdx(LPBYTE pPeBuf, DWORD rva)
{
	if (rva == 0) return -1;
	auto pSecHeader = getSectionHeader(pPeBuf);
	WORD n = getSectionNum(pPeBuf);
	for (int i = 0; i < n - 1; i++)
	{
		if (pSecHeader[i].VirtualAddress <= rva
			&& pSecHeader[i + 1].VirtualAddress > rva) return i;
	}
	if (pSecHeader[n - 1].VirtualAddress <= rva) return n - 1;
	else return -1;
}

DWORD CPEinfo::getPeMemSize(const char* path)
{
	BYTE buf[PEHBUF_SIZE];
	readFile(path, buf, PEHBUF_SIZE);
	return getPeMemSize(buf);
}

DWORD CPEinfo::getPeMemSize(LPBYTE pPeBuf)
{
	if (pPeBuf == NULL) return 0;
	if (isPe((LPBYTE)pPeBuf) <= 0) return 0;
	return getOptionalHeader(pPeBuf)->SizeOfImage;
}

DWORD CPEinfo::getOverlaySize(const char* path)
{
	BYTE buf[PEHBUF_SIZE];
	DWORD filesize;

	filesize = getFileSize(path);
	if (filesize == 0) return 0;
	readFile(path, buf, PEHBUF_SIZE);
	int res = isPe(buf);
	if (res > 0) return getOverlaySize(buf, filesize);
	return res;
}

DWORD CPEinfo::getOverlaySize(LPBYTE pFileBuf, DWORD filesize)
{
	PIMAGE_FILE_HEADER pFileHeader = getFileHeader(pFileBuf);
	PIMAGE_SECTION_HEADER pSectionHeader = getSectionHeader(pFileBuf);
	WORD sec_num = pFileHeader->NumberOfSections;
	DWORD olaysize = filesize - (
		pSectionHeader[sec_num - 1].PointerToRawData +
		pSectionHeader[sec_num - 1].SizeOfRawData);
	return olaysize;
}

DWORD CPEinfo::readOverlay(const char* path, LPBYTE pOverlayBuf)
{
	if (pOverlayBuf == NULL) return 0;
	DWORD filesize = getFileSize(path);
	if (filesize == 0) return 0;
	LPBYTE pFileBuf = new BYTE[filesize];
	readFile(path, pFileBuf, filesize);
	int res = isPe(pFileBuf);
	if (res > 0)
	{
		res = readOverlay(pFileBuf, filesize, pOverlayBuf);
	}
	delete[] pFileBuf;
	return res;
}

DWORD CPEinfo::readOverlay(LPBYTE pFileBuf, DWORD filesize, LPBYTE pOverlayBuf)
{
	DWORD olaysize = getOverlaySize(pFileBuf, filesize);
	if (olaysize > 0) memcpy(pOverlayBuf, pFileBuf + filesize - olaysize, olaysize);
	return olaysize;
}

DWORD CPEinfo::rva2faddr(const char* path, DWORD rva)
{
	BYTE buf[PEHBUF_SIZE];
	int size = readFile(path, buf, PEHBUF_SIZE);
	if (size == 0) return 0;
	return rva2faddr(buf, rva);
}

DWORD CPEinfo::rva2faddr(LPBYTE pPeBuf, DWORD rva)
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pPeBuf);
	if (rva <= pOptionalHeader->SectionAlignment) return rva;//pe头部分
	DWORD rvaoff;//rva相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pPeBuf);
	WORD sec_num = getFileHeader(pPeBuf)->NumberOfSections;
	for (int i = 0; i < sec_num; i++)
	{
		rvaoff = rva - pSecHeader[i].VirtualAddress;
		if (rvaoff >= 0 && rvaoff <= pSecHeader[i].Misc.VirtualSize)
		{
			return rvaoff + pSecHeader[i].PointerToRawData;
		}
	}
	return 0;
}

DWORD CPEinfo::faddr2rva(const char* path, DWORD faddr)
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) <= 0) return 0;
	return faddr2rva(buf, faddr);
}

DWORD CPEinfo::faddr2rva(LPBYTE pPeBuf, DWORD faddr)
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = getOptionalHeader(pPeBuf);
	if (faddr <= pOptionalHeader->FileAlignment) return faddr;
	DWORD faddroff;//faddr相对挂载点偏移
	PIMAGE_SECTION_HEADER pSecHeader = getSectionHeader(pPeBuf);
	WORD sec_num = getFileHeader(pPeBuf)->NumberOfSections;
	for (int i = 0; i < sec_num; i++)
	{
		faddroff = faddr - pSecHeader[i].PointerToRawData;
		if (faddroff >= 0 && faddroff <= pSecHeader[i].SizeOfRawData)
		{
			return faddroff + pSecHeader[i].VirtualAddress;
		}
		i++;
	}
	return 0;
}
#ifdef _WIN64
DWORD CPEinfo::va2rva(const char* path, ULONGLONG va)
#else
DWORD CPEinfo::va2rva(const char* path, DWORD va)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2rva(buf, va);
}

#ifdef _WIN64
DWORD CPEinfo::va2rva(LPBYTE pPeBuf, ULONGLONG va)
#else
DWORD CPEinfo::va2rva(LPBYTE pPeBuf, DWORD va)
#endif
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return (DWORD)(va - getOptionalHeader(pPeBuf)->ImageBase);
}

#ifdef _WIN64
ULONGLONG CPEinfo::rva2va(const char* path, DWORD rva)
#else
DWORD CPEinfo::rva2va(const char* path, DWORD rva)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return rva2va(buf, rva);
}

#ifdef _WIN64
ULONGLONG CPEinfo::rva2va(LPBYTE pPeBuf, DWORD rva)
#else
DWORD CPEinfo::rva2va(LPBYTE pPeBuf, DWORD rva)
#endif
{
	if (pPeBuf == NULL) return 0;
	if (isPe(pPeBuf) <= 0) return 0;
	return rva + getOptionalHeader(pPeBuf)->ImageBase;
}

#ifdef _WIN64
ULONGLONG CPEinfo::faddr2va(const char* path, DWORD faddr)
#else
DWORD CPEinfo::faddr2va(const char* path, DWORD faddr)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return faddr2va(buf, faddr);
}

#ifdef _WIN64
ULONGLONG CPEinfo::faddr2va(LPBYTE pPeBuf, DWORD faddr)
#else
DWORD CPEinfo::faddr2va(LPBYTE pPeBuf, DWORD faddr)
#endif
{
	if (pPeBuf == NULL) return 0;
	return rva2va(pPeBuf, faddr2rva(pPeBuf, faddr));
}

#ifdef _WIN64
DWORD CPEinfo::va2faddr(const char* path, ULONGLONG va)
#else
DWORD CPEinfo::va2faddr(const char* path, DWORD va)
#endif
{
	BYTE buf[PEHBUF_SIZE];
	if (readFile(path, buf, PEHBUF_SIZE) == 0) return 0;
	return va2faddr(buf, va);
}
#ifdef _WIN64
DWORD CPEinfo::va2faddr(LPBYTE pPeBuf, ULONGLONG va)
#else
DWORD CPEinfo::va2faddr(LPBYTE pPeBuf, DWORD va)
#endif
{
	if (pPeBuf == NULL) return 0;
	return rva2faddr(pPeBuf, va2rva(pPeBuf, va));
}
/*Static end*/

/* constructors*/
CPEinfo::CPEinfo(const char* path, bool isMemAlign)
{
	CPEinfo();
	openPeFile(path, isMemAlign);
}

CPEinfo::CPEinfo(LPBYTE pPeBuf, DWORD filesize, bool isCopyMem, bool isMemAlign)
{
	CPEinfo();
	attachPeBuf(pPeBuf, filesize, isCopyMem, isMemAlign);
}
void CPEinfo::copy(const CPEinfo& pe, bool isCopyMem)//默认拷贝函数
{
	attachPeBuf(pe.getPeBuf(), pe.getPeBufSize(),
		isCopyMem, pe.isMemAlign(),
		pe.getOverlayBuf(), pe.getOverlayBufSize());
	strcpy(this->m_szFilePath, pe.m_szFilePath);
}
CPEinfo::CPEinfo(const CPEinfo& pe)
{
	copy(pe, true);
}

CPEinfo& CPEinfo::operator=(CPEinfo& pe)
{
	copy(pe, true);
	return *this;
}
/* constructors end*/

/*public functions*/
void CPEinfo::iniValue()
{
	m_bMemAlign = true;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
	m_bMemAlloc = true;//是否内存为此处分配的

	memset(m_szFilePath, 0, MAX_PATH);
	m_pPeBuf = 0;		//PE文件缓冲区
	m_dwPeBufSize = 0;	//PE文件缓存区大小
	m_pOverlayBuf = NULL;	//PE附加数据
	m_dwOverlayBufSize = 0; //PE附加数据大小
}

DWORD CPEinfo::openPeFile(const char* path, bool bMemAlign)//暂时不用内存映射，不用loadPeFile函数，若是filealign节省一次内存载入	
{
	//释放之前资源
	closePeFile();
	m_bMemAlign = bMemAlign;
	m_bMemAlloc = true;

	DWORD filesize = getFileSize(path);
	DWORD loadsize = 0;
	LPBYTE pFileBuf = new BYTE[filesize];
	if (readFile(path, (LPBYTE)pFileBuf, 0) <= 0) return -3;
	if (CPEinfo::isPe((LPBYTE)pFileBuf) > 0)
	{
		DWORD last_faddr;
		auto pNtHeader = CPEinfo::getNtHeader(pFileBuf);
		auto pSecHeader = CPEinfo::getSectionHeader(pFileBuf);
		DWORD memsize = pNtHeader->OptionalHeader.SizeOfImage;
		WORD sec_num = pNtHeader->FileHeader.NumberOfSections;

		//一定区段索引地址按照从小到大顺序，rva，faddr都是
		last_faddr = pSecHeader[sec_num - 1].PointerToRawData + pSecHeader[sec_num - 1].SizeOfRawData;
		if (bMemAlign == false)
		{
			m_pPeBuf = pFileBuf;
			m_dwPeBufSize = last_faddr;
			m_dwOverlayBufSize = filesize - last_faddr;
			if (last_faddr < filesize)
			{
				m_pOverlayBuf = pFileBuf + last_faddr;
				m_dwOverlayBufSize = filesize - last_faddr;
			}
			loadsize = filesize;
		}
		else
		{
			loadsize = memsize;
			m_dwPeBufSize = memsize;
			m_pPeBuf = new BYTE[memsize];
			memset(m_pPeBuf, 0, memsize);
			memcpy(m_pPeBuf, pFileBuf, pNtHeader->OptionalHeader.SizeOfHeaders);
			for (WORD i = 0; i < sec_num; i++)//赋值
			{
				memcpy(m_pPeBuf + pSecHeader[i].VirtualAddress,
					pFileBuf + pSecHeader[i].PointerToRawData,
					pSecHeader[i].SizeOfRawData);

			}
			if (last_faddr < filesize)
			{
				m_dwOverlayBufSize = filesize - last_faddr;
				m_pOverlayBuf = new BYTE[m_dwOverlayBufSize];
				memcpy(m_pOverlayBuf, pFileBuf + last_faddr, m_dwOverlayBufSize);
				loadsize += m_dwOverlayBufSize;
			}
			delete[] pFileBuf;
		}
	}
	return loadsize;
}

int CPEinfo::attachPeBuf(LPBYTE pPeBuf, DWORD dwFileBufSize,
	bool bCopyMem, bool bMemAlign,
	LPBYTE pOverlayBuf, DWORD dwOverLayBufSize)
{
	if (pPeBuf == NULL) return 0;
	m_bMemAlloc = bCopyMem;
	m_bMemAlign = bMemAlign;
	closePeFile();
	int res = isPe((LPBYTE)pPeBuf);
	if (res > 0)
	{
		if (bCopyMem)
		{
			m_pPeBuf = new BYTE[dwFileBufSize];
			memcpy(m_pPeBuf, pPeBuf, dwFileBufSize);
			if (dwOverLayBufSize > 0)
			{
				m_pOverlayBuf = new BYTE[dwOverLayBufSize];
				memcpy(m_pOverlayBuf, pOverlayBuf, dwOverLayBufSize);
			}
		}
		else
		{
			m_pPeBuf = pPeBuf;
			m_pOverlayBuf = pOverlayBuf;
		}
		m_dwPeBufSize = dwFileBufSize;
		m_dwOverlayBufSize = dwOverLayBufSize;
	}
	return res;
}

void CPEinfo::closePeFile()
{
	memset(m_szFilePath, 0, MAX_PATH);
	if (m_bMemAlloc == true && m_pPeBuf != NULL) delete[] m_pPeBuf;
	if (m_bMemAlloc == true && m_pOverlayBuf != NULL) delete[] m_pOverlayBuf;
	m_pPeBuf = NULL;
	m_dwPeBufSize = 0;
	m_pOverlayBuf = NULL;
	m_dwOverlayBufSize = 0;
}

int CPEinfo::isPe()
{
	return CPEinfo::isPe(m_pPeBuf);
}

bool CPEinfo::isMemAlign() const
{
	return m_bMemAlign;//载入的pe文件是否为内存对齐，暂时只写内存对齐吧。。
}

bool CPEinfo::isMemAlloc() const
{
	return m_bMemAlloc;//是否内存为此处分配的
}

const char* const CPEinfo::getFilePath() const
{
	return m_szFilePath;
}

LPBYTE CPEinfo::getPeBuf() const
{
	return m_pPeBuf;//PE文件缓冲区
}

DWORD CPEinfo::getAlignSize() const
{
	return m_bMemAlign ?
		const_cast<CPEinfo*>(this)->getOptionalHeader()->SectionAlignment :
		const_cast<CPEinfo*>(this)->getOptionalHeader()->FileAlignment;
}

DWORD CPEinfo::toAlign(DWORD num) const
{
	return toAlign(num, getAlignSize());
}

DWORD CPEinfo::getPeBufSize() const
{
	return m_dwPeBufSize;//PE文件缓存区大小
}

DWORD CPEinfo::getPeMemSize()const
{
	return getPeMemSize(m_pPeBuf);
}

LPBYTE CPEinfo::getOverlayBuf() const
{
	return m_pOverlayBuf;
}

DWORD CPEinfo::getOverlayBufSize() const
{
	return m_dwOverlayBufSize;
}

PIMAGE_NT_HEADERS CPEinfo::getNtHeader()
{
	return getNtHeader(m_pPeBuf);
}

PIMAGE_FILE_HEADER CPEinfo::getFileHeader()
{
	return getFileHeader(m_pPeBuf);
}

PIMAGE_OPTIONAL_HEADER CPEinfo::getOptionalHeader()
{
	return getOptionalHeader(m_pPeBuf);
}

PIMAGE_DATA_DIRECTORY CPEinfo::getImageDataDirectory()
{
	return getImageDataDirectory(m_pPeBuf);
}

PIMAGE_SECTION_HEADER CPEinfo::getSectionHeader()
{
	return getSectionHeader(m_pPeBuf);
}

PIMAGE_IMPORT_DESCRIPTOR CPEinfo::getImportDescriptor()
{
	return getImportDescriptor(m_pPeBuf, m_bMemAlign);
}

PIMAGE_EXPORT_DIRECTORY CPEinfo::getExportDirectory()
{
	return getExportDirectory(m_pPeBuf, m_bMemAlign);
}

DWORD CPEinfo::getOepRva()
{
	return getOepRva(m_pPeBuf);
}

WORD  CPEinfo::getSectionNum()
{
	return getSectionNum(m_pPeBuf);
}
int  CPEinfo::findRvaSectIdx(DWORD rva)
{
	return findRvaSectIdx(m_pPeBuf, rva);
}


DWORD CPEinfo::rva2faddr(DWORD rva) const
{
	return rva2faddr(m_pPeBuf, rva);
}

DWORD CPEinfo::faddr2rva(DWORD faddr) const
{
	return faddr2rva(m_pPeBuf, faddr);

}
#ifdef _WIN64
DWORD CPEinfo::va2rva(ULONGLONG va) const
{
	return va2rva(m_pPeBuf, va);
}

ULONGLONG CPEinfo::rva2va(DWORD rva) const
{
	return rva2va(m_pPeBuf, rva);
}

ULONGLONG CPEinfo::faddr2va(DWORD faddr) const
{
	return faddr2va(m_pPeBuf, faddr);
}

DWORD CPEinfo::va2faddr(ULONGLONG va) const
{
	return va2faddr(m_pPeBuf, va);
}
#else
DWORD CPEinfo::va2rva(DWORD va) const
{
	return va2rva(m_pPeBuf, va);
}

DWORD CPEinfo::rva2va(DWORD rva) const
{
	return rva2va(m_pPeBuf, rva);
}

DWORD CPEinfo::faddr2va(DWORD faddr) const
{
	return faddr2va(m_pPeBuf, faddr);
}

DWORD CPEinfo::va2faddr(DWORD va) const
{
	return va2faddr(m_pPeBuf, va);
}
#endif
/*public functions end*/