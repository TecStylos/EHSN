#include "packetQueue.h"

namespace EHSN {
	namespace net {

		bool operator<(const PacketHeader& left, const PacketHeader& right)
		{
			return left.packetID < right.packetID;
		}

		PacketQueue::PacketQueue(Ref<SecSocket> sock)
			: m_sock(sock), m_sendPool(1), m_recvPool(1)
		{
			if (m_sock->isConnected())
				pushRecvJob();
		}

		PacketQueue::~PacketQueue()
		{
			disconnect();
		}

		Ref<SecSocket> PacketQueue::getSock()
		{
			return m_sock;
		}

		bool PacketQueue::connect(const std::string& host, const std::string& port, bool noDelay)
		{
			disconnect();

			bool ret = m_sock->connect(host, port, noDelay);
			if (m_sock->isConnected())
				pushRecvJob();

			return ret;
		}

		void PacketQueue::disconnect()
		{
			m_sock->disconnect();
			m_recvPool.clear();
		}

		PacketID PacketQueue::push(PacketType packetType, PacketFlags flags, Ref<PacketBuffer> buffer)
		{
			PacketHeader header;
			header.packetType = packetType;
			header.flags = flags;

			return push(header, buffer);
		}

		PacketID PacketQueue::push(PacketHeader& header, Ref<PacketBuffer> buffer)
		{
			Packet pack;
			pack.header = header;
			pack.header.packetID = m_nextPacketID++;
			pack.header.packetSize = buffer->size();
			pack.buffer = buffer;

			m_sendPool.pushJob(std::bind(&PacketQueue::sendFunc, this, pack));

			return pack.header.packetID;
		}

		Packet PacketQueue::pull(PacketType packType)
		{
			Packet pack;
			while (!pack.buffer && m_sock->isConnected())
			{
				std::unique_lock<std::mutex> lock(m_mtxRecvQueue);
				auto typeIterator = m_recvQueue.find(packType);
				if (typeIterator != m_recvQueue.end() &&
					!typeIterator->second.empty())
				{
					pack = typeIterator->second.front();
					typeIterator->second.pop();
				}
				else
				{
					m_recvNotify.wait(lock, [this] { return m_recvAvail || !m_sock->isConnected(); });
					m_recvAvail = false;
				}
			}

			return pack;
		}

		uint64_t PacketQueue::nAvailable(PacketType packType)
		{
			std::unique_lock<std::mutex> lock(m_mtxRecvQueue);
			auto typeIterator = m_recvQueue.find(packType);
			if (typeIterator == m_recvQueue.end())
				return 0;
			return typeIterator->second.size();
		}

		void PacketQueue::wait(PacketID packetID)
		{
			std::unique_lock<std::mutex> lock(m_mtxPacketIDBeingSent);

			m_sentNotify.wait(lock, [this, packetID](){ return packetID < m_currPacketIDBeingSent; });
		}

		void PacketQueue::clear()
		{
			m_sendPool.clear();

			{
				std::unique_lock<std::mutex> lock(m_mtxRecvQueue);
				while (!m_recvQueue.empty())
				{
					auto i = m_recvQueue.begin();
					while (!i->second.empty())
						i->second.pop();
					m_recvQueue.erase(i);
				}
			}
		}

		void PacketQueue::setSentCallback(PacketType pType, PacketSentCallback cb, void* pParam)
		{
			std::unique_lock<std::mutex> lock(m_mtxSentCallbacks);

			CallbackData<PacketSentCallback> cd;
			cd.callback = cb;
			cd.pParam = pParam;

			if (cb)
				m_sentCallbacks.emplace(pType, cd);
			else
				m_sentCallbacks.erase(pType);
		}

		void PacketQueue::setRecvCallback(PacketType pType, PacketRecvCallback cb, void* pParam)
		{
			std::unique_lock<std::mutex> lock(m_mtxSentCallbacks);

			CallbackData<PacketRecvCallback> cd;
			cd.callback = cb;
			cd.pParam = pParam;

			if (cb)
				m_recvCallbacks.emplace(pType, cd);
			else
				m_recvCallbacks.erase(pType);
		}

		bool PacketQueue::callSentCallback(const Packet& pack, bool success)
		{
			setCurrentPacketBeingSent(m_currPacketIDBeingSent + 1);

			std::unique_lock<std::mutex> lock(m_mtxSentCallbacks);

			auto iterator = m_sentCallbacks.find(pack.header.packetType);
			if (iterator == m_sentCallbacks.end())
				return false;

			iterator->second.callback(pack.header.packetID, success, iterator->second.pParam);
			return true;
		}

		bool PacketQueue::callRecvCallback(Packet& pack, bool success)
		{
			std::unique_lock<std::mutex> lock(m_mtxRecvCallbacks);

			auto iterator = m_recvCallbacks.find(pack.header.packetType);
			if (iterator == m_recvCallbacks.end())
				return false;
			iterator->second.callback(pack, success, iterator->second.pParam);
			return true;
		}

		void PacketQueue::sendFunc(Packet packet)
		{
			m_currPacketIDBeingSent = packet.header.packetID;

			if (packet.buffer)
			{
				if (!m_sock->writeSecure(&packet.header, sizeof(PacketHeader)))
				{
					callSentCallback(packet, false);
					return;
				}
				if (!m_sock->writeSecure(packet.buffer))
				{
					callSentCallback(packet, false);
					return;
				}
				callSentCallback(packet, true);
			}
		}

		void PacketQueue::recvFunc()
		{
			Packet pack;

			if (!m_sock->isConnected())
				return;

			if (!m_sock->readSecure(&pack.header, sizeof(pack.header)))
				return;

			if (pack.header.packetSize > 0)
			{
				pack.buffer = std::make_shared<PacketBuffer>(pack.header.packetSize); // TODO: Aquire buffer from pool

				if (!m_sock->readSecure(pack.buffer))
				{
					callRecvCallback(pack, false);
					return;
				}
			}

			if (!callRecvCallback(pack, true))
			{
				{
					std::unique_lock<std::mutex> lock(m_mtxRecvQueue);

					auto typeIterator = m_recvQueue.find(pack.header.packetType);
					if (typeIterator == m_recvQueue.end())
						typeIterator = m_recvQueue.emplace(pack.header.packetType, std::queue<Packet>()).first;

					if (pack.header.flags & FLAG_PH_REMOVE_PREVIOUS)
					{
						while (!typeIterator->second.empty())
							typeIterator->second.pop();
					}
					typeIterator->second.push(pack);

					m_recvAvail = true;
				}
				m_recvNotify.notify_one();

			}

			if (m_sock->isConnected())
				pushRecvJob();
		}

		void PacketQueue::pushRecvJob()
		{
			m_recvPool.pushJob(std::bind(&PacketQueue::recvFunc, this));
		}

		void PacketQueue::setCurrentPacketBeingSent(PacketID pID)
		{
			{
				std::unique_lock<std::mutex> lock(m_mtxPacketIDBeingSent);
				m_currPacketIDBeingSent = pID;
			}
			m_sentNotify.notify_all();
		}
	} // namespace net
} // namespace EHSN