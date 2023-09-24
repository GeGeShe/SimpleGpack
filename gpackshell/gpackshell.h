#include <Windows.h>
#define GPACK_API __declspec(dllexport)
#define DLZMANOPACK
#ifndef _SIMPLEDPACKSHELL_H
#define _SIMPLEDPACKSHELL_H
extern "C" {
#include "gpacktype.h"
	void BeforeUnpack(); // 解压前的操作，比如说加密解密相关
	void AfterUnpack(); // 解压后操作
	void JmpOrgOep();// 跳转到源程序
}
void MallocAll(PVOID arg); // 预分配内存
void UnpackAll(PVOID arg); // 解压所有区段
void LoadOrigionIat(PVOID arg);	// 加载原来的iat
#endif