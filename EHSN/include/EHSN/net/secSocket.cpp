#include "secSocket.h"

#include "EHSN/crypto/rsa.h"

namespace EHSN {
	namespace net {

		SecSocket::SecSocket(crypto::RandomDataGenerator rdg, uint32_t nCryptThreads)
			: m_sock(IOContext::get()), m_rdg(rdg)
		{
			if (nCryptThreads > 0)
				m_cryptData.threadPool = std::make_shared<ThreadPool>(nCryptThreads);
		}

		bool SecSocket::connect(const std::string& host, const std::string& port, bool noDelay)
		{
			setConnected(false);

			// Resolve hostname
			tcp::resolver resolver(IOContext::get());
			tcp::resolver::query query(tcp::v4(), host, port);
			asio::error_code ec;
			tcp::resolver::iterator iterator = resolver.resolve(query, ec);
			if (ec)
				return false;

			// Connect to host
			asio::connect(m_sock, iterator, ec);
			m_sock.set_option(tcp::no_delay(noDelay));
			setConnected(!ec);

			if (isConnected())
				establishSecureConnection();
			return isConnected();
		}

		void SecSocket::disconnect()
		{
			asio::error_code ec;
			m_sock.shutdown(tcp::socket::shutdown_both, ec);
			m_sock.close();
			setConnected(false);
		}

		bool SecSocket::isConnected() const
		{
			return m_isConnected;
		}

		bool SecSocket::isSecure() const
		{
			return !!m_cryptData.aesKey;
		}

		uint64_t SecSocket::readSecure(Ref<PacketBuffer> buffer)
		{
			return readSecure(buffer->data(), buffer->size());
		}

		uint64_t SecSocket::readSecure(void* buffer, uint64_t nBytes)
		{
			uint64_t nRead = readRaw(buffer, crypto::aes::paddedSize(nBytes));
			if (nRead) autoDecrypt(buffer, nRead, buffer, m_cryptData.aesKey, true);

			return (nRead >= nBytes) ? nBytes : nRead;
		}

		uint64_t SecSocket::writeSecure(Ref<PacketBuffer> buffer)
		{
			return writeSecure(buffer->data(), buffer->size());
		}

		uint64_t SecSocket::writeSecure(void* buffer, uint64_t nBytes)
		{
			uint64_t nEncrypted = autoEncrypt(buffer, nBytes, buffer, m_cryptData.aesKey, true);
			uint64_t nWritten = writeRaw(buffer, nEncrypted);

			return nWritten;
		}

		packets::IPAddress SecSocket::getRemoteIP() const
		{
			packets::IPAddress ipa;

			auto remoteEndpoint = m_sock.remote_endpoint();
			auto remoteAddress = remoteEndpoint.address();
			auto remoteV4 = remoteAddress.to_v4();

			ipa.uint = remoteV4.to_uint();

			return ipa;
		}

		const DataMetrics& SecSocket::getDataMetrics() const
		{
			return m_dataMetrics;
		}

		void SecSocket::resetDataMetrics()
		{
			m_dataMetrics.reset();
		}

		uint64_t SecSocket::readRaw(void* buffer, uint64_t nBytes)
		{
			asio::error_code ec;

			uint64_t nRead = asio::read(m_sock, asio::buffer(buffer, nBytes), ec);

			if (ec)
				setConnected(false);

			m_dataMetrics.addRead(nRead);

			return nRead;
		}

		uint64_t SecSocket::writeRaw(const void* buffer, uint64_t nBytes)
		{
			asio::error_code ec;

			uint64_t nWritten = asio::write(m_sock, asio::buffer(buffer, nBytes), ec);

			if (ec)
				setConnected(false);

			m_dataMetrics.addWritten(nWritten);

			return nWritten;
		}

		uint64_t SecSocket::autoEncrypt(const void* clearData, uint64_t nBytes, void* cipherData, Ref<crypto::aes::Key> key, bool pad)
		{
			if (m_cryptData.threadPool)
				return crypto::aes::encryptThreaded(clearData, nBytes, cipherData, key, pad, m_cryptData.threadPool->size(), m_cryptData.threadPool);
			return crypto::aes::encrypt(clearData, nBytes, cipherData, key, pad);
		}

		uint64_t SecSocket::autoDecrypt(const void* cipherData, uint64_t nBytes, void* clearData, Ref<crypto::aes::Key> key, bool pad)
		{
			if (m_cryptData.threadPool)
				return crypto::aes::decryptThreaded(cipherData, nBytes, clearData, key, pad, m_cryptData.threadPool->size(), m_cryptData.threadPool);
			return crypto::aes::decrypt(cipherData, nBytes, clearData, key, pad);
		}

		void SecSocket::setConnected(bool state)
		{
			m_isConnected = state;
		}

		void SecSocket::setAES(const char* keyRaw, uint64_t keySize)
		{
			m_cryptData.aesKey = std::make_shared<crypto::aes::Key>(keyRaw, keySize);
		}

		bool SecSocket::establishSecureConnection()
		{
			uint32_t aesKeySize;
			uint32_t aesKeyEchoSize;

			if (!escHandshake(&aesKeySize, &aesKeyEchoSize))
				return false;

			if (!escKeyExchange(aesKeySize, aesKeyEchoSize))
				return false;

			return true;
		}

		bool SecSocket::escHandshake(uint32_t* pAesKeySize, uint32_t* pAesKeyEchoSize)
		{
			// Receive the handshake info
			packets::HandshakeInfo hsi, hsiComp;
			readRaw(&hsi, sizeof(hsi));

			// Check for invalid data
			if (strcmp(hsi.host, hsiComp.host))
				return false;

			// Retrieve AES-Key info
			*pAesKeySize = hsi.aesKeySize;
			*pAesKeyEchoSize = hsi.aesKeyEchoSize;

			// Send the handshake reply
			packets::HandshakeReply hsr;
			hsr.hostLocalTime = hsi.hostLocalTime;
			writeRaw(&hsr, sizeof(hsr));

			return true;
		}

		bool SecSocket::escKeyExchange(uint32_t aesKeySize, uint32_t aesKeyEchoSize)
		{
			Ref<crypto::rsa::Key> rsaKey;

			{ // Receive public RSA-Key
				uint64_t rsaStrLen;
				readRaw(&rsaStrLen, sizeof(rsaStrLen));
				if (rsaStrLen > 2048)
					return false;
				char buff[2048];
				readRaw(buff, rsaStrLen);
				buff[rsaStrLen - 1] = '\0';

				std::string rsaStr = buff;

				rsaKey = crypto::rsa::Key::loadFromString(rsaStr, crypto::rsa::KeyType::Public);
			}

			{ // Send encrypted AES-Key to server and validate reply
				if (aesKeySize + aesKeyEchoSize > (uint32_t)rsaKey->getMaxPlainBuffSize())
					return false;

				unsigned int buffDecSize = aesKeySize + aesKeyEchoSize;
				char* buffDec = new char[buffDecSize];

				// Generate a random AES-Key
				m_rdg(buffDec, aesKeySize);

				// Generate a random echo msg
				m_rdg(&buffDec[aesKeySize], aesKeyEchoSize);

				m_cryptData.aesKey = std::make_shared<crypto::aes::Key>(buffDec, aesKeySize);

				// Encrypt AES-Key and echo msg
				char* buffEnc = new char[rsaKey->getMaxCipherBuffSize()];
				uint64_t buffEncSize = crypto::rsa::encrypt(buffDec, buffDecSize, buffEnc, rsaKey);

				// Send RSA-encrypted AES-Key and echo msg
				writeRaw(&buffEncSize, sizeof(buffEncSize));
				writeRaw(buffEnc, buffEncSize);

				delete[] buffEnc;

				char* buffEcho = new char[aesKeyEchoSize];

				// Receive aes-encrypted echo msg
				readSecure(buffEcho, aesKeyEchoSize);

				// Compare original echo msg to newly received
				bool echoIsValid = true;
				for (uint64_t i = 0; i < aesKeyEchoSize; ++i)
				{
					if (buffEcho[i] != buffDec[aesKeySize + i])
					{
						echoIsValid = false;
						break;
					}
				}

				delete[] buffDec;

				if (!echoIsValid)
					return false;
			}

			return true;
		}

	} // namespace net
} // namespace EHSN