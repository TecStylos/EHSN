#include "aesKey.h"

#include <cassert>

#include <cstring>

namespace crypto {
	namespace aes {

		Key::Key(const char* key, size_t size)
		{
			m_rawKey = new char[size];
			m_rawSize = size;
			memcpy(m_rawKey, key, size);

			AES_set_encrypt_key((const unsigned char*)key, (int)size * 8, &m_keyEnc);
			AES_set_decrypt_key((const unsigned char*)key, (int)size * 8, &m_keyDec);
		}

		Key::~Key() {
			memset(m_rawKey, 0, m_rawSize);
			delete[] m_rawKey;
		}

		int Key::getBlockSize() const
		{
			return AES_BLOCK_SIZE;
		}

		Ref<Key> Key::create(const std::vector<char>& key)
		{
			assert(key.size() == 32);
			return std::make_shared<Key>(key.data(), 32);
		}

	} // namespace aes

} // namespace crypto