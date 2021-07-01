#include "rsaKey.h"

#include <fstream>
#include <openssl/pem.h>

namespace EHSN {
	namespace crypto {
		namespace rsa {

			Key::Key(KeyType kt)
			{
				m_type = kt;
			}

			Key::~Key()
			{
				if (m_rsa)
					RSA_free(m_rsa);
			}

			std::string Key::toString() const
			{
				BIO* bio = BIO_new(BIO_s_mem());

				switch (m_type)
				{
				case KeyType::Public:
					PEM_write_bio_RSAPublicKey(bio, m_rsa);
					break;
				case KeyType::Private:
					PEM_write_bio_RSAPrivateKey(bio, m_rsa, NULL, NULL, 0, NULL, NULL);
					break;
				}

				int length = BIO_pending(bio);

				std::string keyStr;
				keyStr.resize(length);
				BIO_read(bio, (void*)keyStr.c_str(), length);

				BIO_free(bio);

				return keyStr;
			}

			int Key::getMaxPlainBuffSize() const
			{
				return getMaxCipherBuffSize() - 42;
			}

			int Key::getMaxCipherBuffSize() const
			{
				return RSA_size(m_rsa);
			}

			int Key::getPadding() const
			{
				return m_padding;
			}

			KeyType Key::getType() const
			{
				return m_type;
			}

			KeyPair Key::generate(int nBits)
			{
				KeyPair kp;
				kp.keyPublic = std::make_shared<Key>(KeyType::Public);
				kp.keyPrivate = std::make_shared<Key>(KeyType::Private);

				RSA* rsa = NULL;
				BIGNUM* bn = NULL;
				unsigned long e = RSA_F4;

				bn = BN_new();
				BN_set_word(bn, e);

				rsa = RSA_new();
				RSA_generate_key_ex(rsa, nBits, bn, NULL);

				BIO* bio = BIO_new(BIO_s_mem());

				PEM_write_bio_RSAPublicKey(bio, rsa);
				PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
				kp.keyPublic->m_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
				kp.keyPrivate->m_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

				BIO_free(bio);

				RSA_free(rsa);
				BN_free(bn);

				return kp;
			}

			KeyRef Key::loadFromFile(const std::string& filepath, KeyType kt)
			{
				std::ifstream file(filepath);
				if (!file.good())
					return nullptr;

				std::string rsaStr;
				while (!file.eof())
				{
					std::string line;
					std::getline(file, line);
					rsaStr += line;
				}

				return loadFromString(rsaStr, kt);
			}
			KeyRef Key::loadFromString(const std::string& keyStr, KeyType kt)
			{
				auto key = std::make_shared<Key>(kt);

				BIO* bio = BIO_new(BIO_s_mem());
				BIO_write(bio, keyStr.c_str(), (int)keyStr.size() + 1);

				switch (kt)
				{
				case KeyType::Public:
					key->m_rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
					break;
				case KeyType::Private:
					key->m_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
					break;
				}

				BIO_free(bio);

				return key;
			}

		} // namespace rsa
	} // namespace crypto
} // namespace EHSN