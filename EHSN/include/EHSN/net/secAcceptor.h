#pragma once

#include <cstdint>

#include "secSocket.h"
#include "EHSN/crypto.h"

namespace EHSN {
	namespace net {

		constexpr uint32_t AES_KEY_SIZE = 32;
		constexpr uint32_t AES_KEY_ECHO_SIZE = 64;

		typedef void(*SessionFunc)(SecSocketRef sock, void* pParam);
		typedef void(*ExceptionCallback)(std::exception& e, SecSocketRef, void* pParam);

		class SecAcceptor
		{
		public:
			/*
			* Constructor of SecAcceptor
			*
			* @param port Port to bind the acceptor to.
			* @param sFunc User defined function that gets called after a secure connection was established.
			* @param pParam User defined data passed to sFunc and ecb calls. May be NULL.
			* @param ecb User defined exception callback for non-handled std::exception's in sFunc. May be NULL.
			* @param rdg Random data generator used for generating the keys. (Currently unused)
			* @param rsaKeySize Size of the RSA key to generate.
			*/
			SecAcceptor(const std::string& port, SessionFunc sFunc, void* pParam, ExceptionCallback ecb, crypto::RandomDataGenerator rdg = crypto::defaultRDG, int rsaKeySize = 4096);
			~SecAcceptor() = default;
		public:
			/*
			* Create a new session.
			*
			* Immediately starts the new session in a separate thread after a client connects.
			* This function is blocking.
			*
			* @param noDelay If set to true latency may be improved, but bandwidth usage increased.
			* @param nCryptThreads Number of threads used for en-/decryption per session/socket.
			*/
			void newSession(bool noDelay = false, uint32_t nCryptThreads = 0);
			/*
			* Get the port the acceptor is assigned to
			* 
			* @returns Port of the acceptor.
			*/
			uint16_t getPort() const;
		private:
			/*
			* Run the session.
			*
			* This function gets called by newSession().
			* It catches all std::exception's and calls ecb if the user defined SessionFunc doesn't catch them.
			* After an exception got catched the function returns.
			*
			* @param sock Socket of the connection.
			* @param keyPair rsa-keypair used to establish a secure connection.
			* @param sFunc User defined function that gets called after a secure connection was established.
			* @param pParam User defined data that can be used by sFunc and ecb. May be NULL.
			* @param ecb User defined exception callback for non-handled std::exception's in sFunc. May be NULL.
			*/
			static void internalSessionFunc(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair, SessionFunc sFunc, void* pParam, ExceptionCallback ecb);
			/*
			* Establish a secure connection with the client.
			*
			* Executes handshake and exchanges rsa-/aes-keys with the client.
			*
			* @param sock Socket of the connection.
			* @param keyPair rsa-keypair used to establish a secure connection.
			* @returns True when a secure connection could be established. Otherwise false.
			*/
			static bool establishSecureConnection(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair);
			/*
			* Execute the handshake with the client.
			*
			* @param sock Socket of the connection.
			* @returns True when the handshake was successful. Otherwise false.
			*/
			static bool escHandshake(SecSocketRef sock);
			/*
			* Exchange rsa-/aes-keys with the client.
			*
			* @param sock Socket of the connection.
			* @param keyPair rsa-keypair used to establish a secure connection.
			* @returns True when the keys were exchanged successfully. Otherwise false.
			*/
			static bool escKeyExchange(SecSocketRef sock, const crypto::rsa::KeyPair& keyPair);
		private:
			tcp::acceptor m_acceptor;
			SessionFunc m_sFunc;
			void* m_pParam;
			ExceptionCallback m_ecb;
			crypto::rsa::KeyPair m_rsaKeyPair;
			crypto::RandomDataGenerator m_rdg;
		};

	} // namespace net
} // namespace EHSN