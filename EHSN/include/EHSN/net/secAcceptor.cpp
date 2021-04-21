#include "secAcceptor.h"

namespace net {

	SecAcceptor::SecAcceptor(unsigned short port, SessionFunc sFunc, void* pParam, ExceptionCallback ecb)
		: m_acceptor(IOContext::get(), tcp::endpoint(tcp::v4(), port)), m_sFunc(sFunc), m_pParam(pParam), m_ecb(ecb)
	{
		assert(m_sFunc != nullptr);

		m_rsaKeyPair = crypto::rsa::Key::generate(4096);
	}

	void SecAcceptor::internalSessionFunc(Ref<SecSocket> sock, const crypto::rsa::KeyPair& keyPair, SessionFunc sFunc, void* pParam, ExceptionCallback ecb)
	{
		try
		{
			if (!establishSecureConnection(sock, keyPair))
				throw std::exception();

			sFunc(sock, pParam);
		}
		catch (std::exception& e)
		{
			if (ecb != nullptr)
				ecb(e, sock, pParam);
		}
	}

	bool SecAcceptor::establishSecureConnection(Ref<SecSocket> sock, const crypto::rsa::KeyPair& keyPair)
	{
		if (!escHandshake(sock))
			return false;

		if (!escKeyExchange(sock, keyPair))
			return false;

		return true;
	}

	bool SecAcceptor::escHandshake(Ref<SecSocket> sock)
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

	bool SecAcceptor::escKeyExchange(Ref<SecSocket> sock, const crypto::rsa::KeyPair& keyPair)
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

	void SecAcceptor::newSession(bool noDelay)
	{
		auto sock = std::make_shared<SecSocket>();
		m_acceptor.accept(sock->m_sock);
		sock->m_sock.set_option(tcp::no_delay(noDelay));
		sock->setConnected(true);
		std::thread t(std::bind(internalSessionFunc, sock, m_rsaKeyPair, m_sFunc, (void*)m_pParam, m_ecb));
		t.detach();
	}

} // namespace net