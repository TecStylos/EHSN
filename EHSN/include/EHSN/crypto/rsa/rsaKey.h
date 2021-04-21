#ifndef RSAKEY_H
#define RSAKEY_H

#include <string>

#include "EHSN/Reference.h"
#include "ossl_rsa_include.h"

namespace crypto {
	namespace rsa {

		class Key;

		enum class KeyType {
			None,
			Public,
			Private
		};

		struct KeyPair {
			Ref<Key> keyPublic;
			Ref<Key> keyPrivate;
		};

		class Key {
		public:
			Key(KeyType kt);
			~Key();
		public:
			std::string toString() const;
			int getMaxPlainBuffSize() const;
			int getMaxCipherBuffSize() const;
			int getPadding() const;
			KeyType getType() const;
		private:
			RSA* m_rsa = NULL;
			KeyType m_type = KeyType::None;
			const int m_padding = RSA_PKCS1_OAEP_PADDING;
		public:
			static KeyPair generate(int nBits);
			static Ref<Key> loadFromFile(const std::string& filepath, KeyType kt);
			static Ref<Key> loadFromString(const std::string& keyStr, KeyType kt);
		private:
			friend int encrypt(const void*, int, void*, const Ref<Key>);
			friend int decrypt(const void*, int, void*, const Ref<Key>);
		};

	} // namespace rsa
} // namespace crypto

#endif // RSAKEY_H