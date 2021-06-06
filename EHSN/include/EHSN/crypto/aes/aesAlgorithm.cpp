#include "aesAlgorithm.h"

#include <cassert>
#include <future>
#include "EHSN/ThreadPool.h"

namespace EHSN {
	namespace crypto {
		namespace aes {
			uint64_t crypt(const void* from, uint64_t nBytes, void* to, Ref<Key> key, bool pad, CryptBlockFunc func)
			{
				assert(pad || nBytes % AES_BLOCK_SIZE == 0);
				if (pad)
					nBytes = paddedSize(nBytes);

				for (int i = 0; i < nBytes; i += AES_BLOCK_SIZE)
				{
					func((const char*)from + i, (char*)to + i, key);
				}

				return nBytes;
			}

			uint64_t cryptThreaded(const void* cipherData, uint64_t nBytes, void* clearData, Ref<Key> key, bool pad, uint64_t nJobs, Ref<ThreadPool> threadPool, CryptBlockFunc func)
			{
				assert(pad || nBytes % AES_BLOCK_SIZE == 0);
				if (pad)
					nBytes = paddedSize(nBytes);

				uint64_t nBlocks = nBytes / AES_BLOCK_SIZE;
				uint64_t nBlocksPerJob = nBlocks / nJobs;
				uint64_t nBytesPerJob = nBlocksPerJob * AES_BLOCK_SIZE;
				uint64_t nBytesLastJob = nBytes - nBytesPerJob * (nJobs - 1);

				if (nBlocksPerJob == 0)
					return crypt(cipherData, nBytes, clearData, key, false, func);

				uint64_t lastJobNum = 0;
				for (uint64_t i = 0; i < nJobs; ++i)
				{
					lastJobNum = threadPool->pushJob(
						[func, cipherData, i, nJobs, nBytesLastJob, nBytesPerJob, clearData, key]()
						{
							bool isLastJob = (i == nJobs - 1);
							crypt(
								cipherData,
								isLastJob ? nBytesLastJob : nBytesPerJob,
								clearData,
								key,
								false,
								func
							);
						}
					);
					cipherData = (char*)cipherData + nBytesPerJob;
					clearData = (char*)clearData + nBytesPerJob;
				}

				threadPool->wait(lastJobNum);

				return nBytes;
			}

		} // namespace aes
	} // namespace crypto
} // namespace EHSN