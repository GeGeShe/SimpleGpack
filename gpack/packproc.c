#include <Windows.h>
#include <stdio.h>
#include "gpacktype.h"
#include "zstd.h"

size_t zstdPack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
    int const compressionLevel = ZSTD_maxCLevel();
    PZSTD_HEADER pZstdh = (PZSTD_HEADER)pDstBuf;
    pZstdh->RawDataSize = srcSize;

    size_t maxCSize = ZSTD_compressBound(srcSize);  // 获取最大可能的压缩后大小
    if (maxCSize == 0) {
        fprintf(stderr, "Failed to get maximum compressed size.\n");
        return 0;
    }

    size_t const cSize = ZSTD_compress(pDstBuf + sizeof(ZSTD_HEADER), maxCSize, pSrcBuf, srcSize, compressionLevel);
    if (ZSTD_isError(cSize))
    {
        fprintf(stderr, "error compressing: %s\n", ZSTD_getErrorName(cSize));
        return 0;
    }

    pZstdh->CompressedSize = cSize;
    return sizeof(ZSTD_HEADER) + cSize;
}