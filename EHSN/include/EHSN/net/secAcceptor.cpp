#include "secAcceptor.h"

namespace EHSN {
	namespace net {

		SecAcceptor::SecAcceptor(const std::string& port, SessionFunc sFunc, void* pParam, ExceptionCallback ecb, crypto::RandomDataGenerator rdg)
			: m_acceptor(IOContext::get(), tcp::endpoint(tcp::v4(), std::stoi(port))), m_sFunc(sFunc), m_pParam(pParam), m_ecb(ecb), m_rdg(rdg)
		{
			assert(m_sFunc != nullptr);

			m_rsaKeyPair = crypto::rsa::Key::generate(4096);
		}

		void SecAcceptor::internalSessionFunc(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair, SessionFunc sFunc, void* pParam, ExceptionCallback ecb)
		{
			auto callEcb = [&ecb, &sock, pParam](std::exception& e)
			{
				if (ecb != nullptr)
					ecb(e, sock, pParam);
			};

			try
			{
				if (!establishSecureConnection(sock, keyPair))
					throw std::runtime_error("Unable to establish a secure connection!");

				sFunc(sock, pParam);
			}
			catch (std::exception& e)
			{
				callEcb(e);
			}
			catch (...)
			{
				std::runtime_error e("Unknown exception thrown in sessionFunc! Catched with (...)!");
				callEcb(e);
			}
		}

		bool SecAcceptor::establishSecureConnection(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair)
		{
			if (!escHandshake(sock))
				return false;

			if (!escKeyExchange(sock, keyPair))
				return false;

			return true;
		}

		bool SecAcceptor::escHandshake(SecSocketRef sock)
		{
			packets::HandshakeInfo hsi;
			hsi.aesKeySize = AES_KEY_SIZE;
			hsi.aesKeyEchoSize = AES_KEY_ECHO_SIZE;
			hsi.hostLocalTime = time(NULL);
			hsi.clientIP = sock->getRemoteIP();

			packets::HandshakeReply hsr;

			sock->writeRaw(&hsi, sizeof(hsi));
			sock->readRaw(&hsr, sizeof(hsr));

			if (strcmp(hsi.host, hsr.host))
				return false;
			if (hsi.hostLocalTime != hsr.hostLocalTime)
				return false;

			return true;
		}

		bool SecAcceptor::escKeyExchange(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair)
		{
			{ // Send public RSA-Key to client
				std::string rsaStr = keyPair.keyPublic->toString();
				uint64_t rsaStrLen = rsaStr.size() + 1;

				sock->writeRaw(&rsaStrLen, sizeof(rsaStrLen));
				sock->writeRaw(rsaStr.c_str(), rsaStrLen);
			}

			{ // Receive encrypted AES-Key and validate it
				uint64_t buffEncSize;
				sock->readRaw(&buffEncSize, sizeof(buffEncSize));

				if (buffEncSize > keyPair.keyPublic->getMaxCipherBuffSize())
					return false;

				char* buffEnc = new char[buffEncSize];
				char buffDec[AES_KEY_SIZE + AES_KEY_ECHO_SIZE];

				// Receive RSA-encrypted AES-Key and echo msg
				sock->readRaw(buffEnc, buffEncSize);
				crypto::rsa::decrypt(buffEnc, (int)buffEncSize, buffDec, keyPair);

				delete[] buffEnc;

				// Add AES-Key to the socket
				sock->setAES(&buffDec[0], AES_KEY_SIZE);
				memset(buffDec, 0, AES_KEY_SIZE);

				// Send AES-encrypted echo msg to client
				sock->writeSecure(&buffDec[AES_KEY_SIZE], AES_KEY_ECHO_SIZE);
			}

			return true;
		}

		void SecAcceptor::newSession(bool noDelay, uint32_t nCryptThreads)
		{
			auto sock = std::make_shared<SecSocket>(crypto::defaultRDG, nCryptThreads);
			m_acceptor.accept(sock->m_sock);
			sock->m_sock.set_option(tcp::no_delay(noDelay));
			sock->setConnected(true);
			std::thread t(std::bind(internalSessionFunc, sock, m_rsaKeyPair, m_sFunc, (void*)m_pParam, m_ecb));
			t.detach();
		}

	} // namespace net
} // namespace EHSN