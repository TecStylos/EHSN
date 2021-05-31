#include "aesAlgorithm.h"

#include <cassert>
#include <future>

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

		void cryptThreaded(const void* cipherData, int nBytes, void* clearData, Ref<Key> key, int nThreads, CryptFunc func)
		{
			assert(nBytes % AES_BLOCK_SIZE == 0);
			assert(nThreads <= CRYPTO_MAX_THREADS);

			std::future<void> threads[CRYPTO_MAX_THREADS];

			int nBlocks = nBytes / AES_BLOCK_SIZE;
			int nBlocksPerThread = nBlocks / nThreads;
			int nBytesPerThread = nBlocksPerThread * AES_BLOCK_SIZE;
			int nBytesLastThread = nBytes - nBytesPerThread * (nThreads - 1);

			if (nBlocksPerThread == 0)
			{
				func(cipherData, nBytes, clearData, key);
				return;
			}

			for (int i = 0; i < nThreads; ++i)
			{
				threads[i] = std::async(
					std::launch::async,
					func,
					cipherData,
					(i == nThreads - 1) ? nBytesLastThread : nBytesPerThread,
					clearData,
					key
				);
				cipherData = (char*)cipherData + nBytesPerThread;
				clearData = (char*)clearData + nBytesPerThread;
			}

			for (int i = 0; i < nThreads; ++i)
				threads[i].wait();
		}

	} // namespace aes
} // namespace crypto