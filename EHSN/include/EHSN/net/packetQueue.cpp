#include "packetQueue.h"

namespace net {

	bool operator<(const PacketHeader& left, const PacketHeader& right)
	{
		if (left.priorityLevel == right.priorityLevel)
		{
			return left.packetID < right.packetID;
		}

		return left.priorityLevel < right.priorityLevel;
	}

	PacketQueue::PacketQueue(Ref<SecSocket> sock)
		: m_sock(sock)
	{
		start();
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
		start();

		return ret;
	}

	void PacketQueue::disconnect()
	{
		m_sock->disconnect();
		stop();
	}

	PacketID PacketQueue::push(PacketType packetType, PriorityLevel priorityLevel, PacketFlags flags, PacketBuffer buffer)
	{
		PacketHeader header;
		header.packetType = packetType;
		header.priorityLevel = priorityLevel;
		header.flags = flags;

		return push(header, buffer);
	}

	PacketID PacketQueue::push(PacketHeader& header, PacketBuffer buffer)
	{
		header.packetID = m_nextPacketID++;
		header.packetSize = buffer.size();
		{
			std::unique_lock<std::mutex> lock(m_mtxSendQueue);
			m_sendQueue.emplace(header, buffer); // TODO: Check if remove_previous flag is set

			m_sendAvail = true;
		}
		m_sendNotify.notify_one();

		return header.packetID;
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
				m_recvNotify.wait(lock, [this] { return m_recvAvail || m_stopThreads || !m_sock->isConnected(); });
				m_recvAvail = false;
			}
		}

		pack.buffer.setReturnToQueue(true);

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

	void PacketQueue::wait(PriorityLevel priorityLevel, PacketID packetID)
	{
		PacketHeader ph;
		ph.priorityLevel = priorityLevel;
		ph.packetID = packetID;

		std::unique_lock<std::mutex> lock(m_mtxSendQueue);
		m_sentNotify.wait(lock, [this, &ph] { return (m_sendQueue.find(ph) == m_sendQueue.end()) && (ph.packetID != m_currPacketIDBeingSent); });
	}

	PacketBuffer PacketQueue::acquireBuffer(uint64_t minSize)
	{
		PacketBuffer buffer;
		{
			std::unique_lock<std::mutex> lock(m_mtxUnusedBuffers);
			auto iterator = m_unusedBuffers.lower_bound(minSize);

			if (iterator == m_unusedBuffers.end())
			{
				if (m_unusedBuffers.empty())
					return PacketBuffer(minSize, this);
				--iterator;
			}

			buffer = iterator->second.front();
			iterator->second.pop();
			if (iterator->second.empty())
				m_unusedBuffers.erase(iterator);
		}

		buffer.resize(minSize);

		buffer.setReturnToQueue(true);

		return buffer;
	}

	void PacketQueue::releaseBuffer(PacketBuffer buffer)
	{
		buffer.setReturnToQueue(false);

		std::unique_lock<std::mutex> lock(m_mtxUnusedBuffers);

		auto iterator = m_unusedBuffers.find(buffer.reserved());
		if (iterator == m_unusedBuffers.end())
			iterator = m_unusedBuffers.emplace(buffer.reserved(), std::queue<PacketBuffer>()).first;
		iterator->second.push(buffer);
	}

	void PacketQueue::clear()
	{
		{
			std::unique_lock<std::mutex> lock(m_mtxSendQueue);
			while (!m_sendQueue.empty())
				m_sendQueue.erase(m_sendQueue.begin());
		}
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

	void PacketQueue::sendFunc()
	{
		while (m_sock->isConnected() && !m_stopThreads)
		{
			Packet pack;
			{
				std::unique_lock<std::mutex> lock(m_mtxSendQueue);
				if (!m_sendQueue.empty())
				{
					auto pair = *m_sendQueue.begin();
					pack.header = pair.first;
					pack.buffer = pair.second;
					m_sendQueue.erase(m_sendQueue.begin());
				}
				else
				{
					m_sendNotify.wait(lock, [this] { return m_sendAvail || m_stopThreads || !m_sock->isConnected(); });
					m_sendAvail = false;
				}
				m_currPacketIDBeingSent = pack.header.packetID;
			}
			if (pack.buffer)
			{
				if (!m_sock->writeSecure(&pack.header, sizeof(pack.header)))
				{
					callSentCallback(pack, false);
					break;
				}

				if (!m_sock->writeSecure(pack.buffer))
				{
					callSentCallback(pack, false);
					break;
				}
			}
			callSentCallback(pack, true);
			setCurrentPacketBeingSent(0);
		}
		if (!m_sock->isConnected())
			notifyThreads();

		setCurrentPacketBeingSent(0);
	}

	void PacketQueue::recvFunc()
	{
		while (m_sock->isConnected() && !m_stopThreads)
		{
			Packet pack;

			if (!m_sock->readSecure(&pack.header, sizeof(pack.header)))
				break;

			if (pack.header.packetSize > 0)
			{
				pack.buffer = acquireBuffer(pack.header.packetSize);

				if (!m_sock->readSecure(pack.buffer))
				{
					callRecvCallback(pack, false);
					break;
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
		}
		if (!m_sock->isConnected())
			notifyThreads();
	}

	void PacketQueue::notifyThreads()
	{
		m_sendNotify.notify_one();
		m_recvNotify.notify_one();
	}

	void PacketQueue::setCurrentPacketBeingSent(PacketID pID)
	{
		{
			std::unique_lock<std::mutex> lock(m_mtxSendQueue);
			m_currPacketIDBeingSent = pID;
		}
		if (pID == 0)
			m_sentNotify.notify_one();

	}

	void PacketQueue::start()
	{
		m_stopThreads = false;

		m_sendThread = std::thread(&PacketQueue::sendFunc, this);
		m_recvThread = std::thread(&PacketQueue::recvFunc, this);
	}

	void PacketQueue::stop()
	{
		m_stopThreads = true;

		m_sendNotify.notify_one();
		m_recvNotify.notify_one();

		if (m_sendThread.joinable())
			m_sendThread.join();
		if (m_recvThread.joinable())
			m_recvThread.join();
	}

} // namespace net