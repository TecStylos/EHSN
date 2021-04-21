#ifndef RSAALGORITHM_H
#define RSAALGORITHM_H

#include "rsaKey.h"

namespace crypto {
	namespace rsa {

		int encrypt(const void* clearData, int nBytes, void* cipherData, const KeyPair& keyPair);
		int decrypt(const void* cipherData, int nBytes, void* clearData, const KeyPair& keyPair);

		int encrypt(const void* clearData, int nBytes, void* cipherData, const Ref<Key> keyPublic);
		int decrypt(const void* cipherData, int nBytes, void* clearData, const Ref<Key> keyPrivate);

	} // namespace rsa
} // namespace crypto

#endif // RSAALGORITHM_H