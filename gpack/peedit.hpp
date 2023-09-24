#include "PeInfo.hpp"
#ifndef _PEEDIT_H
#define _PEEDIT_H
class CPEedit :public CPEinfo
{
public:
	static DWORD addOverlay(const char* path, LPBYTE pOverlay, DWORD size);
	static DWORD setOepRva(const char* path, DWORD rva);
	static DWORD setOepRva(LPBYTE pPeBuf, DWORD rva);//返回原来的rvas
	static DWORD shiftReloc(LPBYTE pPeBuf, size_t oldImageBase, size_t newImageBase,
		DWORD offset, bool bMemAlign = true); // 将reloc记录以及reloc指向的地址进行基址变换
	static DWORD shiftOft(LPBYTE pPeBuf, DWORD offset, bool bMemAlign = true, bool bResetFt = true); // 将IAT进行基址变换, 返回修改iat数量
	//添加区段，返回添加的区段后的总字节数，假设区段索引不会超过第一个区段，且缓存区足够大
	static DWORD appendSection(LPBYTE pPeBuf, IMAGE_SECTION_HEADER newSectHeader,
		LPBYTE pNewSectBuf, DWORD newSectSize, bool bMemAlign = true);
	// 移除区段数据，返回删除的区段raw size和。不移除header了，因为区段中间有空隙加载pe会出问题
	static DWORD removeSectionDatas(LPBYTE pPeBuf, int removeNum, int removeIdx[]);
	static DWORD savePeFile(const char* path, // 将缓存区中的区段调整并保存成文件
		LPBYTE pFileBuf, DWORD dwFileBufSize,
		bool bMemAlign = false, bool bShrinkPe = true, // 移除空白，如去掉区段索引的部分
		LPBYTE pOverlayBuf = NULL, DWORD OverlayBufSize = 0);//失败返回0，成功返回写入总字节数

public:
	DWORD setOepRva(DWORD rva);
	DWORD shiftReloc(size_t oldImageBase, size_t newImageBase, DWORD offset);
	DWORD shiftOft(DWORD offset, bool bResetFt = true);
	DWORD appendSection(IMAGE_SECTION_HEADER newSectHeader,
		LPBYTE pNewSectBuf, DWORD newSectSize); //添加区段，返回新增区段字节数
	DWORD removeSectionDatas(int removeNum, int removeIdx[]); // 移除区段, removeIdx必须顺序，返回remove后的区段数
	DWORD savePeFile(const char* path, bool bShrinkPe = true); //保存缓冲区pe文件
};
#endif