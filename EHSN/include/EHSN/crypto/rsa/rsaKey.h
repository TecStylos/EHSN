#ifndef RSAKEY_H
#define RSAKEY_H

#include <string>

#include "EHSN/Reference.h"
#include "ossl_rsa_include.h"

namespace EHSN {
	namespace crypto {
		namespace rsa {

			class Key;

			typedef Ref<Key> KeyRef;

			enum class KeyType
			{
				None,
				Public,
				Private
			};

			struct KeyPair
			{
				KeyRef keyPublic;
				KeyRef keyPrivate;
			};

			class Key
			{
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
				static KeyRef loadFromFile(const std::string& filepath, KeyType kt);
				static KeyRef loadFromString(const std::string& keyStr, KeyType kt);
			private:
				friend int encrypt(const void*, int, void*, const KeyRef);
				friend int decrypt(const void*, int, void*, const KeyRef);
			};

		} // namespace rsa
	} // namespace crypto
} // namespace EHSN

#endif // RSAKEY_H