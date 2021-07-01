#ifndef AESALGORITHM_H
#define AESALGORITHM_H

#include "aesKey.h"

#include "EHSN/ThreadPool.h"

namespace EHSN {
	namespace crypto {
		namespace aes {

			typedef void (*CryptBlockFunc)(const void*, void*, KeyRef);
			typedef void (*CryptFunc)(const void*, int, void*, KeyRef, bool);

			inline uint64_t paddedSize(uint64_t nBytes) { return ((nBytes + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; }

			/*
			* Encrypt a data block.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			*/
			inline void encryptBlock(const void* clearData, void* cipherData, KeyRef key) { AES_encrypt((const unsigned char*)clearData, (unsigned char*)cipherData, &key->m_keyEnc); }

			/*
			* Decrypt a data block.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			*/
			inline void decryptBlock(const void* cipherData, void* clearData, KeyRef key) { AES_decrypt((const unsigned char*)cipherData, (unsigned char*)clearData, &key->m_keyDec); }

			/*
			* En-/Decrypt nBytes of data.
			* from and to may point to the same buffer.
			*
			* @param from Pointer to the source data.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE if padded is set to false!
			* @param to Pointer to the destination.
			* @param key Key to encrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @param func The function to use (en-/decryption).
			* @returns Number of en-/decrypted bytes in to buffer.
			*/
			uint64_t crypt(const void* from, uint64_t nBytes, void* to, KeyRef key, bool pad, CryptBlockFunc func);
			/*
			* Encrypt nBytes of data.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE if padded is set to false!
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @returns Number of encrypted bytes in cipherData buffer.
			*/
			inline uint64_t encrypt(const void* clearData, uint64_t nBytes, void* cipherData, KeyRef key, bool pad) { return crypt(clearData, nBytes, cipherData, key, pad, &encryptBlock); }
			/*
			* Decrypt nBytes of data.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE if padded is set to false!
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @returns Number of decrypted bytes in clearData buffer.
			*/
			inline uint64_t decrypt(const void* cipherData, uint64_t nBytes, void* clearData, KeyRef key, bool pad) { return crypt(cipherData, nBytes, clearData, key, pad, &decryptBlock); }

			/*
			* En-/Decrypt nBytes of data.
			* from and to may point to the same buffer.
			*
			* @param from Pointer to the source data.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE if pad is set to false!
			* @param to Pointer to the destination.
			* @param key Key to encrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @param nJobs Number of jobs to use.
			* @param threadPool Thread pool to push the jobs onto.
			* @param func The function to use (en-/decryption).
			* @returns Number of en-/decrypted bytes in to buffer.
			*/
			uint64_t cryptThreaded(const void* from, uint64_t nBytes, void* to, KeyRef key, bool pad, uint64_t nJobs, ThreadPoolRef threadPool, CryptBlockFunc func);
			/*
			* Encrypt nBytes of data.
			* clearData and cipherData may point to the same buffer.
			*
			* @param clearData Pointer to the data to encrypt.
			* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE if padded is set to false!
			* @param cipherData Address where the encrypted data gets stored.
			* @param key Key to encrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @param nJobs Number of jobs to use.
			* @param threadPool Thread pool to push the jobs onto.
			* @returns Number of encrypted bytes in cipherData buffer.
			*/
			inline uint64_t encryptThreaded(const void* clearData, uint64_t nBytes, void* cipherData, KeyRef key, bool pad, int nJobs, ThreadPoolRef threadPool) { return cryptThreaded(clearData, nBytes, cipherData, key, pad, nJobs, threadPool, &encryptBlock); }
			/*
			* Decrypt nBytes of data.
			* cipherData and clearData may point to the same buffer.
			*
			* @param cipherData Pointer to the data to decrypt.
			* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE if padded is set to false!
			* @param clearData Address where the decrypted data gets stored.
			* @param key Key to decrypt the data with.
			* @param pad If set to true nBytes will be padded to the next multiple of AES_BLOCK_SIZE.
			* @param nJobs Number of jobs to use.
			* @param threadPool Thread pool to push the jobs onto.
			* @returns Number of decrypted bytes in clearData buffer.
			*/
			inline uint64_t decryptThreaded(const void* cipherData, uint64_t nBytes, void* clearData, KeyRef key, bool pad, int nJobs, ThreadPoolRef threadPool) { return cryptThreaded(cipherData, nBytes, clearData, key, pad, nJobs, threadPool, &decryptBlock); }
		} // namespace aes

	} // namespace crypto

} // namespace EHSN

#endif // AESALGORITHM_H