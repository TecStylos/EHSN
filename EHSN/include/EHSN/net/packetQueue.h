#ifndef PACKETQUEUE_H
#define PACKETQUEUE_H

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

		struct PacketHeader
		{
			PacketType packetType = 0;
			PacketFlags flags = FLAG_PH_NONE;
			uint8_t reserved;
			PacketID packetID = 0;
			uint64_t packetSize = 0;
		};

		constexpr int PacketHeaderSize = sizeof(PacketHeader);
		#if PacketHeaderSize % 16 != 0
		#error "sizeof(PacketHeaderSize) must be a multiple of 16!"
		#endif

		bool operator<(const PacketHeader& left, const PacketHeader& right);

		struct Packet
		{
			PacketHeader header;
			Ref<PacketBuffer> buffer;
		};

		enum STANDARD_PACKET_TYPES : PacketType
		{
			SPT_UNDEFINED = 0,
			SPT_PING,
			SPT_PING_REPLY,
			SPT_CHANGE_AES_KEY,
			SPT_FIRST_FREE_PACKET_TYPE // Can be used to determine the associated value of the first user-defined packet type.
		};

		class PacketQueue
		{
		public:
			/*
			* This function gets called when a packet was sent.
			*
			* @param pID The ID of the packet that was sent.
			* @param success True if the packet was sent. False when it could not be sent.
			* @param pParam Pointer to user defined data.
			*/
			typedef void (*PacketSentCallback)(PacketID pID, bool success, void* pParam);
			/*
			* This function gets called when a packet was received.
			*
			* @param pack The packet that was received.
			* @param success Set to true if the buffer was received. Otherwise false.
			* @param pParam Pointer to user defined data.
			*/
			typedef void (*PacketRecvCallback)(Packet pack, bool success, void* pParam);

			template<typename T>
			struct CallbackData
			{
				T callback;
				void* pParam;
			};
			/*
			* Constructor of PacketQueue.
			*
			* The supplied socket should only be used when the packet queue is paused.
			*
			* @param sock Socket used for read/write operations.
			*/
			PacketQueue(Ref<SecSocket> sock);
			~PacketQueue();
		public:
			/*
			* Get the underlying socket.
			*
			* @returns The underlying socket.
			*/
			Ref<SecSocket> getSock();
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
			* For speed improvements you should acquire the buffer with calling acquireBuffer.
			*
			* @param packetType Type of the packet to be sent.
			* @param flags Flags determining how to handle this and other packets.
			* @param buffer Packet buffer holding the data to be sent.
			* @returns The packed ID identifying the pushed packet.
			*/
			PacketID push(PacketType packetType, PacketFlags flags, Ref<PacketBuffer> buffer);
			PacketID push(PacketHeader& header, Ref<PacketBuffer> buffer);
			/*
			* Pull a packet from the read-queue.
			*
			* The buffer in the returned packet should be released with calling releaseBuffer.
			* It can also be pushed onto the queue without being released first.
			* This function blocks until a matching buffer is available or the connection is lost.
			*
			* @param packType Type of the packet to be pulled.
			* @returns The first packet with the specified type.
			*/
			Packet pull(PacketType packType);
			/*
			* Get the number of available packets matching the packet type.
			*
			* @param packType The packet type to check for.
			* @returns The number of available packets matching the packet type.
			*/
			uint64_t nAvailable(PacketType packType);
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
			* @param succes Set to true if the packet was successful sent. Otherwise false.
			* @returns True if a corresponding callback was found and called. Otherwise false.
			*/
			bool callSentCallback(const Packet& pack, bool success);
			/*
			* Call the corresponding callback to the packet type.
			*
			* @param pack The packet that has been received/tried to receive.
			* @param success Set to true if the buffer was successful received. Otherwise false.
			* @returns True if a corresponding callback was found and called. Otherwise false.
			*/
			bool callRecvCallback(Packet& pack, bool success);
			/*
			* Thread function for sending packets.
			*/
			void sendFunc(Packet packet);
			/*
			* Thread function for receiving packets.
			*/
			void recvFunc();
			void pushRecvJob();
			/*
			* Sets the ID of the packet currently being sent.
			*
			* If pID is 0 the wait function gets notified that the packet has been sent.
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

			ThreadPool m_sendPool;
			ThreadPool m_recvPool;

			std::mutex m_mtxSentCallbacks;
			std::mutex m_mtxRecvCallbacks;
			std::unordered_map<PacketType, CallbackData<PacketSentCallback>> m_sentCallbacks;
			std::unordered_map<PacketType, CallbackData<PacketRecvCallback>> m_recvCallbacks;
		private:
			std::mutex m_mtxPacketIDBeingSent;
			PacketID m_currPacketIDBeingSent;
			PacketID m_nextPacketID = 1;
			bool m_paused = true;
		private:
			Ref<SecSocket> m_sock;
		};

	} // namespace net
} // namespace EHSN

#endif // PACKETQUEUE_H