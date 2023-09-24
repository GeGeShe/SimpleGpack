#include "gpackshell.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <sstream>
#pragma comment(lib, "Shlwapi.lib")

void dpackStart();

extern "C" {
	GPACK_API GPACK_SHELL_INDEX g_dpackShellIndex = { (PVOID)dpackStart,0 };//顺便初始化壳oep
	ULONGLONG g_orgOep;
}

LPCWSTR GetExeFileName() {
	static WCHAR buffer[MAX_PATH] = { 0 };
	DWORD size = GetModuleFileNameW(NULL, buffer, MAX_PATH);
	if (0 == size) {
		return L"";
	}
	else {
		return PathFindFileNameW(buffer);
	}
}

#ifndef _WIN64
void BeforeUnpack()
#else
void BeforeUnpack()
#endif
{
	/*std::wstringstream ss;
	ss << L"Threat Detected: Backdoor/Nerd.nt" << L"\n\nFile Name: " << GetExeFileName() << L"\n\nThreat Description: Secretly opens ports and permissions for remote control or actively connects to the hacker's control end." << L"\n\nRecommended Action: Immediately quarantine or delete the file to prevent potential harm to your device.";
	MessageBoxW(
		NULL,
		ss.str().c_str(),
		(LPCWSTR)L"Warning",
		MB_OK
	);*/
}

#ifndef _WIN64
__declspec(naked) void AfterUnpack()
#else
void AfterUnpack()
#endif
{

}

#ifndef _WIN64
__declspec(naked) void JmpOrgOep()
{
	__asm
	{
		push g_orgOep;
		ret;
	}
}
#endif

#ifdef _WIN64 
void dpackStart()
#else
__declspec(naked) void dpackStart()//此函数中不要有局部变量
#endif
{
	BeforeUnpack();
	MallocAll(NULL);
	UnpackAll(NULL);
	g_orgOep = static_cast<ULONGLONG>(g_dpackShellIndex.OrgIndex.ImageBase) + g_dpackShellIndex.OrgIndex.OepRva;
	LoadOrigionIat(NULL);
	AfterUnpack();
	JmpOrgOep();
}

void MallocAll(PVOID arg)
{
	MEMORY_BASIC_INFORMATION mi = { 0 };
	HANDLE hProcess = GetCurrentProcess();
	HMODULE imagebase = GetModuleHandle(NULL);
	for (int i = 0; i < g_dpackShellIndex.SectionNum; i++)
	{
		if (g_dpackShellIndex.SectionIndex[i].OrgSize == 0) continue;
		LPBYTE tVa = (LPBYTE)imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva;
		DWORD tSize = g_dpackShellIndex.SectionIndex[i].OrgSize;
		VirtualQueryEx(hProcess, tVa, &mi, tSize);
		if (mi.State == MEM_FREE)
		{
			DWORD flProtect = PAGE_EXECUTE_READWRITE;
			switch (g_dpackShellIndex.SectionIndex[i].Characteristics)
			{
			case IMAGE_SCN_MEM_EXECUTE:
				flProtect = PAGE_EXECUTE;
				break;
			case IMAGE_SCN_MEM_READ:
				flProtect = PAGE_READONLY;
				break;
			case IMAGE_SCN_MEM_WRITE:
				flProtect = PAGE_READWRITE;
				break;
			}
			if (!VirtualAllocEx(hProcess, tVa, tSize, MEM_COMMIT, flProtect))
			{
				MessageBox(NULL, L"Alloc memory failed", L"error", NULL);
				ExitProcess(1);
			}
		}
	}
}

void UnpackAll(PVOID arg)
{
	DWORD oldProtect;
#ifdef _WIN64
	ULONGLONG imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#else
	DWORD imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#endif
	for (int i = 0; i < g_dpackShellIndex.SectionNum; i++)
	{
		switch (g_dpackShellIndex.SectionIndex[i].GpackSectionType)
		{
		case  GPACK_SECTION_RAW:
		{
			if (g_dpackShellIndex.SectionIndex[i].OrgSize == 0) continue;
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((void*)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				(void*)(imagebase + g_dpackShellIndex.SectionIndex[i].GpackRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize);
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				oldProtect, &oldProtect);
			break;
		}
		case GPACK_SECTION_DLZMA:
		{
			LPBYTE buf = new BYTE[g_dpackShellIndex.SectionIndex[i].OrgSize];
			if (!zstdUnpack(buf,
				(LPBYTE)(g_dpackShellIndex.SectionIndex[i].GpackRva + imagebase),
				g_dpackShellIndex.SectionIndex[i].GpackSize))
			{
				MessageBox(0, L"unpack failed", L"error", 0);
				ExitProcess(1);
			}
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((void*)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				buf, g_dpackShellIndex.SectionIndex[i].OrgSize);
			VirtualProtect((LPVOID)(imagebase + g_dpackShellIndex.SectionIndex[i].OrgRva),
				g_dpackShellIndex.SectionIndex[i].OrgSize,
				oldProtect, &oldProtect);
			delete[] buf;
			break;
		}
		default:
			break;
		}
	}
}

void LoadOrigionIat(PVOID arg)  // 因为将iat改为了壳的，所以要还原原来的iat
{
	DWORD i, j;
	DWORD dll_num = g_dpackShellIndex.OrgIndex.ImportSize
		/ sizeof(IMAGE_IMPORT_DESCRIPTOR);//导入dll的个数,含最后全为空的一项
	DWORD item_num = 0;//一个dll中导入函数的个数,不包括全0的项
	DWORD oldProtect;
	HMODULE tHomule;//临时加载dll的句柄
	LPBYTE tName;//临时存放名字
#ifdef _WIN64
	ULONGLONG tVa;//临时存放虚拟地址
	ULONGLONG imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#else
	DWORD tVa;//临时存放虚拟地址
	DWORD imagebase = g_dpackShellIndex.OrgIndex.ImageBase;
#endif
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(imagebase +
		g_dpackShellIndex.OrgIndex.ImportRva);//指向第一个dll
	PIMAGE_THUNK_DATA pfThunk;//ft
	PIMAGE_THUNK_DATA poThunk;//oft
	PIMAGE_IMPORT_BY_NAME pFuncName;
	for (i = 0; i < dll_num; i++)
	{
		if (pImport[i].OriginalFirstThunk == 0) continue;
		tName = (LPBYTE)(imagebase + pImport[i].Name);
		tHomule = LoadLibraryA((LPCSTR)tName);
		pfThunk = (PIMAGE_THUNK_DATA)
			(imagebase + pImport[i].FirstThunk);
		poThunk = (PIMAGE_THUNK_DATA)
			(imagebase + pImport[i].OriginalFirstThunk);
		for (j = 0; poThunk[j].u1.AddressOfData != 0; j++) {}//注意个数。。。
		item_num = j;

		VirtualProtect((LPVOID)(pfThunk),
			item_num * sizeof(IMAGE_THUNK_DATA),
			PAGE_EXECUTE_READWRITE, &oldProtect);//注意指针位置
		for (j = 0; j < item_num; j++)
		{
#ifdef _WIN64
			if ((poThunk[j].u1.Ordinal >> 63) != 0x1) //不是用序号
			{
				pFuncName = (PIMAGE_IMPORT_BY_NAME)(imagebase + poThunk[j].u1.AddressOfData);
				tName = (LPBYTE)pFuncName->Name;
			}
			else
			{
				//如果此参数是一个序数值，它必须在一个字的低字节，高字节必须为0。
				tName = (LPBYTE)(poThunk[j].u1.Ordinal & 0x000000000000ffff);
			}
			tVa = (ULONGLONG)GetProcAddress(tHomule, (LPCSTR)tName);
# else
			if ((poThunk[j].u1.Ordinal >> 31) != 0x1) //不是用序号
			{
				pFuncName = (PIMAGE_IMPORT_BY_NAME)(imagebase + poThunk[j].u1.AddressOfData);
				tName = (LPBYTE)pFuncName->Name;
			}
			else
			{
				//如果此参数是一个序数值，它必须在一个字的低字节，高字节必须为0。
				tName = (LPBYTE)(poThunk[j].u1.Ordinal & 0x0000ffff);
			}
			tVa = (DWORD)GetProcAddress(tHomule, (LPCSTR)tName);
# endif
			if (tVa == NULL)
			{
				MessageBox(NULL, L"IAT load error!", L"error", 0);
				ExitProcess(1);
			}
			pfThunk[j].u1.Function = tVa;//注意间接寻址
		}
		VirtualProtect((LPVOID)(pfThunk),
			item_num * sizeof(IMAGE_THUNK_DATA),
			oldProtect, &oldProtect);
	}
}