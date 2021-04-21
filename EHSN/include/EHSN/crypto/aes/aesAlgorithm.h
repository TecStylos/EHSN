#ifndef AESALGORITHM_H
#define AESALGORITHM_H

#include "aesKey.h"

namespace crypto {
	namespace aes {
		
		/*
		* Encrypt a data block.
		*
		* @param clearData Pointer to the data to encrypt.
		* @param cipherData Address where the encrypted data gets stored.
		* @param key Key to encrypt the data with.
		*/
		inline void encryptBlock(const void* clearData, void* cipherData, Ref<Key> key) { AES_encrypt((const unsigned char*)clearData, (unsigned char*)cipherData, &key->m_keyEnc); }

		/*
		* Decrypt a data block.
		*
		* @param cipherData Pointer to the data to decrypt.
		* @param clearData Address where the decrypted data gets stored.
		* @param key Key to decrypt the data with.
		*/
		inline void decryptBlock(const void* cipherData, void* clearData, Ref<Key> key) { AES_decrypt((const unsigned char*)cipherData, (unsigned char*)clearData, &key->m_keyDec); }

		/*
		* Encrypt a data block in-place.
		*
		* @param data Pointer to the data to encrypt.
		* @param key Key to encrypt the data with.
		*/
		inline void encryptBlock(void* data, Ref<Key> key) { encryptBlock(data, data, key); }
		/*
		* Decrypt a data block in-place.
		*
		* @param data Pointer to the data to decrypt.
		* @param key Key to decrypt the data with.
		*/
		inline void decryptBlock(void* data, Ref<Key> key) { decryptBlock(data, data, key); }

		/*
		* Encrypt nBytes of data.
		*
		* @param clearData Pointer to the data to encrypt.
		* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
		* @param cipherData Address where the encrypted data gets stored.
		* @param key Key to encrypt the data with.
		*/
		void encrypt(const void* clearData, int nBytes, void* cipherData, Ref<Key> key);
		/*
		* Decrypt nBytes of data.
		*
		* @param cipherData Pointer to the data to decrypt.
		* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE!
		* @param clearData Address where the decrypted data gets stored.
		* @param key Key to decrypt the data with.
		*/
		void decrypt(const void* cipherData, int nBytes, void* clearData, Ref<Key> key);

		/*
		* Encrypt nBytes of data in-place.
		*
		* @param data Pointer to the data to encrypt.
		* @param nBytes Number of bytes to encrypt. Must be a multiple of AES_BLOCK_SIZE!
		* @param key Key to encrypt the data with.
		*/
		inline void encrypt(void* data, int nBytes, Ref<Key> key) { encrypt(data, nBytes, data, key); }
		/*
		* Decrypt nBytes of data in-place.
		*
		* @param data Pointer to the data to decrypt.
		* @param nBytes Number of bytes to decrypt. Must be a multiple of AES_BLOCK_SIZE!
		* @param key Key to decrypt the data with.
		*/
		inline void decrypt(void* data, int nBytes, Ref<Key> key) { decrypt(data, nBytes, data, key); }

	} // namespace aes

} // namespace crypto

#endif // AESALGORITHM_H