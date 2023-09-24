#include <Windows.h>
#include "gpacktype.h"
#include "zstd.h"

size_t zstdUnpack(LPBYTE pDstBuf, LPBYTE pSrcBuf, size_t srcSize)
{
    PZSTD_HEADER pzstdh = (PZSTD_HEADER)pSrcBuf;
    size_t dstSize = pzstdh->RawDataSize;

    ZSTD_decompress(pDstBuf, dstSize,
        pSrcBuf + sizeof(ZSTD_HEADER), srcSize - sizeof(ZSTD_HEADER));
    return dstSize;
}