#ifndef SECSOCKET_H
#define SECSOCKET_H

#include <cstdint>
#include <string>

#include "EHSN/crypto.h"

#include "ioContext.h"
#include "packets.h"
#include "packetBuffer.h"

namespace net {

	class DataMetrics {
	public:
		void reset() { m_nRead = 0; m_nWritten = 0; }
		void addRead(uint64_t size) { m_nRead += size; }
		void addWritten(uint64_t size) { m_nWritten += size; }
		uint64_t nRead() const { return m_nRead; };
		uint64_t nWritten() const { return m_nWritten; };
	private:
		uint64_t m_nRead = 0;
		uint64_t m_nWritten = 0;
	};

	class SecSocket {
	public:
		/*
		* Constructor of SecSocket.
		* 
		* @param rdg Random data generator used for generating the keys.
		*/
		SecSocket(crypto::RandomDataGenerator rdg = crypto::defaultRDG);
		~SecSocket() = default;
	public:
		/*
		* Connect to a host.
		*
		* @param host Hostname of the host to connect to.
		* @param port Port of the host to connect to.
		* @param noDelay If set to true latency may be improved, but bandwidth shortened.
		* @returns True when a secure connection could be established. Otherwise false.
		*/
		bool connect(const std::string& host, const std::string& port, bool noDelay = false);
		/*
		* Disconnect from a host (if connected).
		*/
		void disconnect();
		/*
		* Check if the socket is connected.
		*
		* The value gets updated after every read/write from/to the underlying socket.
		* It may not represent the real state of the socket.
		*
		* @returns True when the socket is connected. Otherwise false.
		*/
		bool isConnected() const;
		/*
		* Check if the connection is secure.
		*
		* If no the connection is not secure, no data can be sent/received.
		*
		* @returns True when a secure connection was established. Otherwise false.
		*/
		bool isSecure() const;
	public:
		/*
		* Read encrypted data from the socket and decrypt it.
		*
		* The number of bytes to be read is determined by the size of the buffer.
		*
		* @param buffer The buffer to write the decrypted data to.
		* @returns Number of bytes read from the socket.
		*/
		uint64_t readSecure(PacketBuffer buffer);
		/*
		* Read encrypted data from the socket and decrypt it.
		*
		* @param buffer The buffer to write the decrypted data to.
		* @param nBytes Number of bytes to read from the socket. Must be equal to nBytes of the writeSecure function call on the remote endpoint.
		* @returns Number of bytes read from the socket.
		*/
		uint64_t readSecure(void* buffer, uint64_t nBytes);
		/*
		* Encrypt data in-place and write it to the socket.
		*
		* The number of bytes to be written is determined by the size of the buffer.
		* The data in buffer may be partially or fully changed.
		*
		* @param buffer The buffer to read the data from.
		* @returns Number of bytes written to the socket.
		*/
		uint64_t writeSecure(PacketBuffer buffer);
		/*
		* Encrypt data in-place and write it to the socket.
		*
		* The data in buffer may be partially or fully changed.
		*
		* @param buffer The buffer to encrypt and write to the socket.
		* @param nBytes Number of bytes to write to the socket.
		* @returns Number of bytes written to the socket.
		*/
		uint64_t writeSecure(void* buffer, uint64_t nBytes);
	public:
		/*
		* Get the IP address of the remote endpoint.
		*
		* @returns IP address of the remote endpoint.
		*/
		packets::IPAddress getRemoteIP() const;
		/*
		* Get the data metrics since the last reset.
		*
		* @returns Object holding the data metrics.
		*/
		const DataMetrics& getDataMetrics() const;
		/*
		* Reset the data metrics.
		*/
		void resetDataMetrics();
	protected:
		/*
		* Read raw data from the socket.
		*
		* @param buffer Buffer to write the raw data to.
		* @param nBytes Number of bytes to read from the socket.
		* @returns Number of bytes read from the socket.
		*/
		uint64_t readRaw(void* buffer, uint64_t nBytes);
		/*
		* Write raw data to the socket.
		*
		* @param buffer Buffer to read the data from.
		* @param nBytes Number of bytes to write to the socket.
		* @returns Number of bytes written to the socket.
		*/
		uint64_t writeRaw(const void* buffer, uint64_t nBytes);
	private:
		/*
		* Set the internal connected state.
		*
		* @param state the state of the connection. Set it to true if the connection is working. Otherwise false.
		*/
		void setConnected(bool state);
		/*
		* Set the internal aes-key used for the read-/writeSecure functions.
		*
		* @param keyRaw Buffer of the aes-key
		* @param keySize Size of the buffer
		*/
		void setAES(const char* keyRaw, uint64_t keySize);
		/*
		* Establish a secure connection with the server.
		*
		* Executes handshake and exchanges rsa-/aes-keys with the client.
		*
		* @returns True when a secure connection could be established. Otherwise false.
		*/
		bool establishSecureConnection();
		/*
		* Execute the handshake with the server.
		*
		* @param pAesKeySize Pointer to int where the aesKeySize gets stored.
		* @param pAesKeyEchoSize Pointer to int where the aesKeyEchoSize gets stored.
		* @returns True when the handshake was successful. Otherwise false.
		*/
		bool escHandshake(uint32_t* pAesKeySize, uint32_t* pAesKeyEchoSize);
		/*
		* Exchange rsa-/aes-keys with the server.

		* @param aesKeySize Size of the aes-key to generate.
		* @param aesKeyEchoSize Size of the echo message to generate.
		* @returns True when the keys were exchanged successfully. Otherwise false.
		*/
		bool escKeyExchange(uint32_t aesKeySize, uint32_t aesKeyEchoSize);
	private:
		tcp::socket m_sock;
		bool m_isConnected = false;
		Ref<crypto::aes::Key> m_aesKey;
	private:
		DataMetrics m_dataMetrics;
	private:
		crypto::RandomDataGenerator m_rdg;
	private:
		friend class SecAcceptor;
	};

	/*
	* Write a struct/class or basic data type to the socket.
	*
	* @param sock Socket to write the object to.
	* @param obj Object to read the data from.
	* @returns The same object as sock.
	*/
	template<typename T>
	SecSocket& operator<<(SecSocket& sock, const T& obj)
	{
		char buffer[sizeof(T)];
		memcpy(buffer, &obj, sizeof(T));
		sock.writeSecure(buffer, sizeof(T));
		return sock;
	}

	/*
	* Read a struct/class or basic data type from the socket.
	*
	* @param sock Socket to read the object from.
	* @param obj Object to write the data to.
	* @returns The same object as sock.
	*/
	template<typename T>
	SecSocket& operator>>(SecSocket& sock, T& obj)
	{
		sock.readSecure(&obj, sizeof(T));
		return sock;
	}

} // namespace net

#endif // SECSOCKET_H