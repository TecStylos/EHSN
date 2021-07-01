#ifndef RSAALGORITHM_H
#define RSAALGORITHM_H

#include "rsaKey.h"

namespace EHSN {
	namespace crypto {
		namespace rsa {

			int encrypt(const void* clearData, int nBytes, void* cipherData, const KeyPair& keyPair);
			int decrypt(const void* cipherData, int nBytes, void* clearData, const KeyPair& keyPair);

			int encrypt(const void* clearData, int nBytes, void* cipherData, const KeyRef keyPublic);
			int decrypt(const void* cipherData, int nBytes, void* clearData, const KeyRef keyPrivate);

		} // namespace rsa
	} // namespace crypto
} // namespace EHSN

#endif // RSAALGORITHM_H