#ifndef AESALGORITHM_H
#define AESALGORITHM_H

#include "aesKey.h"

#include "EHSN/ThreadPool.h"

namespace EHSN {
	namespace crypto {
		namespace aes {

			typedef void (*CryptBlockFunc)(const void*, void*, Ref<Key>);
			typedef void (*CryptFunc)(const void*, int, void*, Ref<Key>);

			/*
			* Encrypt a data block.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			*/
			inline void encryptBlock(const void* clearData, void* cipherData, Ref<Key> key) { AES_encrypt((const unsigned char*)clearData, (unsigned char*)cipherData, &key->m_keyEnc); }

			/*
			* Decrypt a data block.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			*/
			inline void decryptBlock(const void* cipherData, void* clearData, Ref<Key> key) { AES_decrypt((const unsigned char*)cipherData, (unsigned char*)clearData, &key->m_keyDec); }

			/*
			* En-/Decrypt nBytes of data.
			* from and to may point to the same buffer.
			*
			* @param from Pointer to the source data.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param to Pointer to the destination.
			* @param key Key to encrypt the data with.
			*/
			void crypt(const void* from, int nBytes, void* to, Ref<Key> key, CryptBlockFunc func);
			/*
			* Encrypt nBytes of data.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			*/
			inline void encrypt(const void* clearData, int nBytes, void* cipherData, Ref<Key> key) { crypt(clearData, nBytes, cipherData, key, &encryptBlock); }
			/*
			* Decrypt nBytes of data.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			*/
			inline void decrypt(const void* cipherData, int nBytes, void* clearData, Ref<Key> key) { crypt(cipherData, nBytes, clearData, key, &decryptBlock); }

			/*
			* En-/Decrypt nBytes of data.
			* from and to may point to the same buffer.
			*
			* @param from Pointer to the source data.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param to Pointer to the destination.
			* @param key Key to encrypt the data with.
			* @param nThreads Number of threads to use.
			*/
			void cryptThreaded(const void* from, int nBytes, void* to, Ref<Key> key, int nJobs, Ref<ThreadPool> threadPool, CryptFunc func);
			/*
			* Encrypt nBytes of data.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			* @param nThreads Number of threads to use.
			*/
			inline void encryptThreaded(const void* clearData, int nBytes, void* cipherData, Ref<Key> key, int nJobs, Ref<ThreadPool> threadPool) { cryptThreaded(clearData, nBytes, cipherData, key, nJobs, threadPool, &encrypt); }
			/*
			* Decrypt nBytes of data.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE!
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			* @param nJobs Number of jobs to use.
			*/
			inline void decryptThreaded(const void* cipherData, int nBytes, void* clearData, Ref<Key> key, int nJobs, Ref<ThreadPool> threadPool) { cryptThreaded(cipherData, nBytes, clearData, key, nJobs, threadPool, &decrypt); }
		} // namespace aes

	} // namespace crypto

} // namespace EHSN

#endif // AESALGORITHM_H