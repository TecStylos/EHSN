#include "aesAlgorithm.h"

#include <cassert>

namespace crypto {
	namespace aes {

		void encrypt(const void* clearData, int nBytes, void* cipherData, Ref<Key> key)
		{
			assert(nBytes % AES_BLOCK_SIZE == 0);

			for (int i = 0; i < nBytes; i += AES_BLOCK_SIZE)
			{
				encryptBlock(clearData, cipherData, key);
			}
		}

		void decrypt(const void* cipherData, int nBytes, void* clearData, Ref<Key> key)
		{
			assert(nBytes % AES_BLOCK_SIZE == 0);

			for (int i = 0; i < nBytes; i += AES_BLOCK_SIZE)
			{
				decryptBlock(cipherData, clearData, key);
			}
		}

	} // namespace aes
} // namespace crypto