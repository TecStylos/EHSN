#pragma once

#include <map>
#include <unordered_map>
#include <queue>
#include <cstdint>

#include "secSocket.h"
#include "packetBuffer.h"
#include "EHSN/ThreadPool.h"

namespace EHSN {
	namespace net {

		typedef uint16_t PacketType;
		typedef uint8_t PacketFlags;
		typedef uint32_t PacketID;

		enum : PacketFlags
		{
			FLAG_PH_NONE = 0b00000000,
			FLAG_PH_REMOVE_PREVIOUS = 0b00000001, // (Packets are only removed on receiver side)
			FLAG_PH_UNUSED_1 = 0b00000010, // FLAG_PH_SEND_IMMEDIATE
			FLAG_PH_UNUSED_2 = 0b00000100,
			FLAG_PH_UNUSED_3 = 0b00001000,
			FLAG_PH_UNUSED_4 = 0b00010000,
			FLAG_PH_UNUSED_5 = 0b00100000,
			FLAG_PH_UNUSED_6 = 0b01000000,
			FLAG_PH_UNUSED_7 = 0b10000000,
		};

		struct PacketHeader // sizeof(PacketHeader) must be a multiple of AES_BLOCK_SIZE!
		{
			PacketType packetType = 0; /* Must be set prior to push. */
			PacketFlags flags = FLAG_PH_NONE; /* Must be set prior to push. */
			uint8_t reserved = 0;
			PacketID packetID = 0;
			uint64_t packetSize = 0;
			float avgWriteSpeed = 1.0f;
			char padding[12];
		};

		bool operator<(const PacketHeader& left, const PacketHeader& right);

		struct Packet
		{
			PacketHeader header;
			PacketBufferRef buffer;
		};

		enum STANDARD_PACKET_TYPES : PacketType
		{
			SPT_UNDEFINED = 0,
			SPT_PING,
			SPT_PING_REPLY,
			SPT_CHANGE_AES_KEY, // Currently unused
			SPT_KEEP_ALIVE_REQUEST, // Can be sent to tell the remote side that the connection should be kept alive. This Type has a built-in recvCallback!
			SPT_KEEP_ALIVE_REPLY, // Sent after a SPT_KEEP_ALIVE_REQUEST has been received (default behavior)
			SPT_FIRST_FREE_PACKET_TYPE // Can be used to determine the associated value of the first user-defined packet type. All previous/smaller values are reserved.
		};

		class ManagedSocket
		{
		public:
			/*
			* This function gets called when a packet was sent.
			*
			* @param pID The ID of the packet that was sent.
			* @param nBytesSent The number of bytes that have been sent. Same value as pack.header.packetSize on success.
			* @param pParam Pointer to user defined data.
			*/
			typedef void (*PacketSentCallback)(PacketID pID, uint64_t nBytesSent, void* pParam);
			/*
			* This function gets called when a packet was received.
			*
			* @param pack The packet that was received.
			* @param nBytesReceived The number of bytes that have been received. Same value as pack.header.packetSize on success.
			* @param pParam Pointer to user defined data.
			*/
			typedef void (*PacketRecvCallback)(Packet pack, uint64_t nBytesReceived, void* pParam);

			template<typename T>
			struct CallbackData
			{
				T callback;
				void* pParam; // Data shared between multiple callbacks (send AND recv) must not be thread safe, as long as it won't be accessed outside of the callbacks. Only one callback is called at a time for the same connection.
			};
			/*
			* Constructor of ManagedSocket.
			*
			* @param sock Socket used for read/write operations.
			* @param nThreads If set to true, packets will be en-/decrypted in a separate thread. For values greater than 0 the passed socket should be created with 0 threads.
			*/
			ManagedSocket(SecSocketRef sock, uint32_t nThreads = 0);
			/*
			* Destructor of PacketQueue.
			* 
			* Closes the underlying socket if open.
			*/
			~ManagedSocket();
		public:
			/*
			* Get the underlying socket.
			*
			* @returns The underlying socket.
			*/
			SecSocketRef getSock();
			/*
			* Connect to a host.
			*
			* @param host Hostname of the host to connect to.
			* @param port Port of the host to connect to.
			* @param noDelay If set to true latency may be improved, but bandwidth shortened.
			* @returns True when a secure connection could be established. Otherwise false.
			*/
			bool connect(const std::string& host, const std::string& port, bool noDelay);
			/*
			* Disconnect from a host (if connected).
			*/
			void disconnect();
			/*
			* Push a packet onto the write-queue.
			*
			* The supplied packet buffer should not be used after calling this function.
			*
			* @param packetType Type of the packet to be sent.
			* @param flags Flags determining how to handle this and other packets.
			* @param buffer Packet buffer holding the data to be sent.
			* @returns The packed ID identifying the pushed packet.
			*/
			PacketID push(PacketType packetType, PacketFlags flags, PacketBufferRef buffer);
			/*
			* Push a packet onto the write-queue.
			* 
			* The supplied packet buffer should not be used after calling this function.
			* 
			* @param pack The packet to send. See PacketHeader for information about what members should get initialized before a push.
			* @returns Unique packet ID. (Can be used to wait until the packet has been sent.)
			*/
			PacketID push(Packet pack);
			/*
			* Pull a packet from the read-queue.
			*
			* This function blocks until a matching buffer is available or the connection is lost.
			* When packType == SPT_UNDEFINED, the first available packet of any type is returned.
			*
			* @param packType Type of the packet to be pulled.
			* @returns The first packet with the specified type.
			*/
			Packet pull(PacketType packType);
			/*
			* Get the number of available packets matching the packet type.
			* When packType == SPT_UNDEFINED, the sum of all available packets gets returned.
			*
			* @param packType The packet type to check for.
			* @returns The number of available packets matching the packet type.
			*/
			uint64_t nPullable(PacketType packType);
			/*
			* Get the packet types for which are one or more packets in the receive queue.
			* 
			* @returns Vector containing every packet type for which one or more packets are in the receive queue.
			*/
			std::vector<PacketType> typesPullable();
			/*
			* Wait until a specific packet has been sent.
			*
			* @param packetID The ID of the packet returned by a call to push.
			*/
			void wait(PacketID packetID);
			/*
			* Clear all incoming/outgoing packets.
			*/
			void clear();
			/*
			* Set the callback for a specific packet type.
			*
			* @param pType The type of the packet to set the callback for.
			* @param cb The callback that is being used when a packet was sent. Use null to remove any existing callbacks for the passed packet type.
			* @param pParam Pointer to user defined data. This pointer is passed to cb.
			*/
			void setSentCallback(PacketType pType, PacketSentCallback cb, void* pParam);
			/*
			* Set the callback for a specific packet type.
			*
			* @param pType The type of the packet to set the callback for.
			* @param cb The callback that is being used when a packet was received. Use null to remove any existing callbacks for the passed packet type.
			* @param pParam Pointer to user defined data. This pointer is passed to cb.
			*/
			void setRecvCallback(PacketType pType, PacketRecvCallback cb, void* pParam);
		private:
			/*
			* Call the corresponding callback to the packet type.
			*
			* @param pack The packet that has been sent/tried to send.
			* @param nBytesSent The number of bytes that have been sent. Same value as pack.header.packetSize on success.
			* @returns True if a corresponding callback was found and called. Otherwise false.
			*/
			bool callSentCallback(const Packet& pack, uint64_t nBytesSent);
			/*
			* Call the corresponding callback to the packet type.
			*
			* @param pack The packet that has been received/tried to receive.
			* @param nBytesReceived The number of bytes that have been received. Same value as pack.header.packetSize on success.
			* @returns True if a corresponding callback was found and called. Otherwise false.
			*/
			bool callRecvCallback(Packet& pack, uint64_t nBytesReceived);
			/*
			* Thread function for sending packets whose buffer is not encrypted.
			*/
			void sendJobEncrypt(Packet packet);
			/*
			* Thread function for sending packets whose buffer is already encrypted.
			*/
			void sendJobNoEncrypt(Packet packet);
			/*
			* Thread function for encrypting packet buffers and creating the corresponding sendJob.
			* 
			* @param packet The packet to encrypt.
			*/
			void makeSendableJob(Packet packet);
			/*
			* Thread function for receiving packets and decrypting them.
			*/
			void recvJobDecrypt();
			/*
			* Thread function for receiving packets and creating a makePullableJob.
			*/
			void recvJobNoDecrypt();
			/*
			* Thread function for decrypting packet buffers and pushing them onto the recvQueue.
			* 
			* @param packet The packet to decrypt.
			* @param nRead The number of bytes that have been read.
			*/
			void makePullableJob(Packet packet, uint64_t nRead);
			/*
			* Push a job onto m_recvPool to keep it alive.
			*/
			void pushRecvJob();
			/*
			* Sets the ID of the packet currently being sent.
			* 
			* Notifies all threads which are waiting on a 'sent' event.
			*
			* @param pID The ID of the packet currently being sent.
			*/
			void setCurrentPacketBeingSent(PacketID pID);
		private:
			bool m_recvAvail = false;
			std::condition_variable m_recvNotify;

			std::mutex m_mtxSent;
			std::condition_variable m_sentNotify;

			std::mutex m_mtxRecvQueue;
			std::map<PacketType, std::queue<Packet>> m_recvQueue;

			ThreadPoolRef m_sendPool;
			ThreadPoolRef m_recvPool;
			ThreadPoolRef m_cryptPool;
			ThreadPoolRef m_cryptThreadPool;
			ThreadPoolRef m_callbackPool;

			std::mutex m_mtxSentCallbacks;
			std::mutex m_mtxRecvCallbacks;
			std::unordered_map<PacketType, CallbackData<PacketSentCallback>> m_sentCallbacks;
			std::unordered_map<PacketType, CallbackData<PacketRecvCallback>> m_recvCallbacks;
		private:
			std::mutex m_mtxPacketIDBeingSent;
			PacketID m_currPacketIDBeingSent = 0;
			PacketID m_nextPacketID = 1;
			bool m_paused = true;
			std::atomic<float> m_remoteWriteSpeed;
		private:
			SecSocketRef m_sock;
		};

	} // namespace net
} // namespace EHSN