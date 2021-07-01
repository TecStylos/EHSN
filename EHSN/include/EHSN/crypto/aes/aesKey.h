#ifndef AESKEY_H
#define AESKEY_H

#include "ossl_aes_include.h"
#include "EHSN/Reference.h"

#include <vector>

namespace EHSN {
	namespace crypto {
		namespace aes {

			class Key;

			typedef Ref<Key> KeyRef;

			class Key
			{
			public:
				Key(const char* key, size_t size);
				~Key();
			public:
				/*
				* Get the number of bytes that can be en-/decrypted with one call.
				*
				* @returns Number of bytes that can be en-/decrypted with one call.
				*/
				int getBlockSize() const;
			private:
				AES_KEY m_keyEnc, m_keyDec;
				char* m_rawKey;
				size_t m_rawSize;
			public:
				/*
				* Create a new aes-key.
				*
				* @param key Data to base the aes-key on.
				* @returns Newly create aes-key.
				*/
				static KeyRef create(const std::vector<char>& key);
			private:
				friend void encryptBlock(const void*, void*, KeyRef);
				friend void decryptBlock(const void*, void*, KeyRef);
			};

		} // namespace aes

	} // namespace crypto

} // namespace EHSN

#endif // AESKEY_H