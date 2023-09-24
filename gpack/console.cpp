#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include "gpack.hpp"

using namespace std;

int main(int argc, char* argv[])
{
	if (argc <= 1)
	{
		cout << "input the exe path and try again!" << endl;
		return 1;
	}
	else
	{
		DWORD res;
		char outpath[MAX_PATH];
		ifstream fin(argv[1]);
		if (fin.fail())
		{
			cout << "#error:invalid path!" << endl;
			return 1;
		}
		CGpack dpack(argv[1]);
#ifdef _WIN64
		res = dpack.packPe("gpackshell64.dll");
#else
		res = dpack.packPe("gpackshell.dll");
#endif
		if (res == 0)
		{
			cout << "#error:pe pack error!" << endl;
			return 2;
		}
		if (argc >= 3)
		{
			strcpy(outpath, argv[2]);
		}
		else
		{
			strcpy(outpath, argv[1]);
			size_t pos = strlen(outpath) - 4;
			if (strcmp(outpath + pos, ".exe"))
			{
				cout << "#error:pe save error!" << endl;
				return 3;
			}
			strcpy(outpath + pos, "_gpack.exe");
		}
		res = dpack.savePe(outpath);
		if (res == 0)
		{
			cout << "#error:pe save error!" << endl;
			return 3;
		}
		cout << "the file packed successfully(0X" << hex << res << " bytes)" << endl;
	}
	return 0;
}

//#include <iostream>
//#include <Windows.h>
//#include <cstring>
//#include "gpacktype.h"
//#include <stdio.h>
//#include "zstd.h"
//
//size_t zstdPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
//{
//    int const compressionLevel = ZSTD_maxCLevel();
//    PZSTD_HEADER pZstdh = (PZSTD_HEADER)pDstBuf;
//    pZstdh->RawDataSize = srcSize;
//
//    size_t maxCSize = ZSTD_compressBound(srcSize);  // 获取最大可能的压缩后大小
//    if (maxCSize == 0) {
//        fprintf(stderr, "Failed to get maximum compressed size.\n");
//        return 0;
//    }
//
//    size_t const cSize = ZSTD_compress(pDstBuf + sizeof(ZSTD_HEADER), maxCSize, pSrcBuf, srcSize, compressionLevel);
//    if (ZSTD_isError(cSize))
//    {
//        fprintf(stderr, "error compressing: %s\n", ZSTD_getErrorName(cSize));
//        return 0;
//    }
//
//    pZstdh->CompressedSize = cSize;
//    return sizeof(ZSTD_HEADER) + cSize;
//}
//
//size_t zstdUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
//{
//    PZSTD_HEADER pzstdh = (PZSTD_HEADER)pSrcBuf;
//    size_t dstSize = pzstdh->RawDataSize;
//
//    ZSTD_decompress(pDstBuf, dstSize,
//        pSrcBuf + sizeof(ZSTD_HEADER), srcSize - sizeof(ZSTD_HEADER));
//    return dstSize;
//}
//
//int main() {
//    char originalData[] = "This is the original data.";
//    size_t srcSize = strlen(originalData) + 1;
//
//    LPBYTE pSrcBuf = (LPBYTE)originalData;
//    LPBYTE pDstBuf = new BYTE[srcSize + sizeof(ZSTD_HEADER)]; // 预留空间给 ZSTD_HEADER 和压缩后的数据
//
//    // 压缩数据
//    size_t packedSize = zstdPack(pDstBuf, pSrcBuf, srcSize);
//    if (packedSize == 0) {
//        std::cerr << "Failed to compress data." << std::endl;
//        delete[] pDstBuf;
//        return 1;
//    }
//
//    // 解压缩数据
//    LPBYTE pDecompressedBuf = new BYTE[srcSize];
//    size_t decompressedSize = zstdUnpack(pDecompressedBuf, pDstBuf, packedSize);
//    if (decompressedSize != srcSize) {
//        std::cerr << "Failed to decompress data." << std::endl;
//        delete[] pDstBuf;
//        delete[] pDecompressedBuf;
//        return 1;
//    }
//
//    // 检查解压缩后的数据是否与原始数据相同
//    if (memcmp(pSrcBuf, pDecompressedBuf, srcSize) != 0) {
//        std::cerr << "Decompressed data does not match original data." << std::endl;
//    }
//    else {
//        std::cout << "Test passed." << std::endl;
//    }
//
//    delete[] pDstBuf;
//    delete[] pDecompressedBuf;
//    return 0;
//}

