#include "rsaAlgorithm.h"

#include <cassert>

namespace EHSN {
	namespace crypto {
		namespace rsa {

			int encrypt(const void* clearData, int nBytes, void* cipherData, const KeyPair& keyPair)
			{
				return encrypt(clearData, nBytes, cipherData, keyPair.keyPublic);
			}

			int decrypt(const void* cipherData, int nBytes, void* clearData, const KeyPair& keyPair)
			{
				return decrypt(cipherData, nBytes, clearData, keyPair.keyPrivate);
			}

			int encrypt(const void* clearData, int nBytes, void* cipherData, const Ref<Key> keyPublic)
			{
				int maxSize = keyPublic->getMaxPlainBuffSize();

				assert(nBytes <= maxSize);
				assert(keyPublic->getType() == KeyType::Public);

				return RSA_public_encrypt(
					nBytes,
					(const unsigned char*)clearData,
					(unsigned char*)cipherData,
					keyPublic->m_rsa,
					keyPublic->getPadding()
				);
			}

			int decrypt(const void* cipherData, int nBytes, void* clearData, const Ref<Key> keyPrivate)
			{
				int maxSize = keyPrivate->getMaxCipherBuffSize();

				assert(nBytes <= maxSize);
				assert(keyPrivate->getType() == KeyType::Private);

				return RSA_private_decrypt(
					nBytes,
					(const unsigned char*)cipherData,
					(unsigned char*)clearData,
					keyPrivate->m_rsa,
					keyPrivate->getPadding()
				);
			}

		} // namespace rsa
	} // namespace crypto
} // namespace EHSN