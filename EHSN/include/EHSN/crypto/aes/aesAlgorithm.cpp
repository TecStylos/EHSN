#include "aesAlgorithm.h"

#include <cassert>
#include <future>
#include "EHSN/ThreadPool.h"

namespace EHSN {
	namespace crypto {
		namespace aes {
			void crypt(const void* from, int nBytes, void* to, Ref<Key> key, CryptBlockFunc func)
			{
				assert(nBytes % AES_BLOCK_SIZE == 0);

				for (int i = 0; i < nBytes; i += AES_BLOCK_SIZE)
				{
					func((const char*)from + i, (char*)to + i, key);
				}
			}

			void cryptThreaded(const void* cipherData, int nBytes, void* clearData, Ref<Key> key, int nJobs, Ref<ThreadPool> threadPool, CryptFunc func)
			{
				assert(nBytes % AES_BLOCK_SIZE == 0);

				int nBlocks = nBytes / AES_BLOCK_SIZE;
				int nBlocksPerJob = nBlocks / nJobs;
				int nBytesPerJob = nBlocksPerJob * AES_BLOCK_SIZE;
				int nBytesLastJob = nBytes - nBytesPerJob * (nJobs - 1);

				if (nBlocksPerJob == 0)
				{
					func(cipherData, nBytes, clearData, key);
					return;
				}

				for (int i = 0; i < nJobs; ++i)
				{
					threadPool->pushJob(
						[func, cipherData, i, nJobs, nBytesLastJob, nBytesPerJob, clearData, key]()
						{
							func(cipherData, (i == nJobs - 1) ? nBytesLastJob : nBytesPerJob, clearData, key);
						}
					);
					cipherData = (char*)cipherData + nBytesPerJob;
					clearData = (char*)clearData + nBytesPerJob;
				}

				threadPool->wait();
			}

		} // namespace aes
	} // namespace crypto
} // namespace EHSN