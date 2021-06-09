#include "managedSocket.h"

namespace EHSN {
	namespace net {

		bool operator<(const PacketHeader& left, const PacketHeader& right)
		{
			return left.packetID < right.packetID;
		}

		ManagedSocket::ManagedSocket(Ref<SecSocket> sock, uint32_t nThreads)
			: m_sock(sock), m_sendPool(1), m_recvPool(1), m_callbackPool(1)
		{
			if (nThreads > 0)
			{
				m_pCryptPool = std::make_shared<ThreadPool>(1);
				m_pCryptThreadPool = std::make_shared<ThreadPool>(nThreads);
			}

			setRecvCallback(
				SPT_KEEP_ALIVE_REQUEST,
				[](Packet pack, bool success, void* pParam)
				{
					if (!success)
						return;

					auto& manSock = *(ManagedSocket*)pParam;
					manSock.push(SPT_KEEP_ALIVE_REPLY, FLAG_PH_NONE, nullptr);
				},
				this
					);

			if (m_sock->isConnected())
				pushRecvJob();
		}

		ManagedSocket::~ManagedSocket()
		{
			disconnect();
		}

		Ref<SecSocket> ManagedSocket::getSock()
		{
			return m_sock;
		}

		bool ManagedSocket::connect(const std::string& host, const std::string& port, bool noDelay)
		{
			disconnect();

			bool ret = m_sock->connect(host, port, noDelay);
			if (m_sock->isConnected())
				pushRecvJob();

			return ret;
		}

		void ManagedSocket::disconnect()
		{
			m_sock->disconnect();
			m_recvPool.clear();
		}

		PacketID ManagedSocket::push(PacketType packetType, PacketFlags flags, Ref<PacketBuffer> buffer)
		{
			Packet pack;
			pack.header.packetType = packetType;
			pack.header.flags = flags;
			pack.buffer = buffer;

			return push(pack);
		}

		PacketID ManagedSocket::push(Packet pack)
		{
			pack.header.packetID = m_nextPacketID++;
			if (pack.buffer)
				pack.header.packetSize = pack.buffer->size();
			else
				pack.header.packetSize = 0;

			if (m_pCryptThreadPool)
				m_pCryptPool->pushJob(std::bind(&ManagedSocket::makeSendableJob, this, pack));
			else
				m_sendPool.pushJob(std::bind(&ManagedSocket::sendJobEncrypt, this, pack));

			return pack.header.packetID;
		}

		Packet ManagedSocket::pull(PacketType packType)
		{
			Packet pack;
			bool gotPack = false;
			while (m_sock->isConnected())
			{
				std::unique_lock<std::mutex> lock(m_mtxRecvQueue);

				if (packType == SPT_UNDEFINED)
				{
					for (auto& it : m_recvQueue)
					{
						if (!it.second.empty())
						{
							pack = it.second.front();
							it.second.pop();
							gotPack = true;
						}
					}
				}
				else
				{
					auto typeIterator = m_recvQueue.find(packType);
					if (typeIterator != m_recvQueue.end() &&
						!typeIterator->second.empty())
					{
						pack = typeIterator->second.front();
						typeIterator->second.pop();
						gotPack = true;
					}
				}

				if (gotPack)
					break;

				m_recvNotify.wait(lock, [this] { return m_recvAvail || !m_sock->isConnected(); });
				m_recvAvail = false;
			}

			return pack;
		}

		uint64_t ManagedSocket::nPullable(PacketType packType)
		{
			std::unique_lock<std::mutex> lock(m_mtxRecvQueue);
			
			if (packType == SPT_UNDEFINED)
			{
				uint64_t nAvail = 0;
				for (auto& it : m_recvQueue)
					nAvail += it.second.size();
				return nAvail;
			}
			
			auto typeIterator = m_recvQueue.find(packType);
			if (typeIterator == m_recvQueue.end())
				return 0;
			return typeIterator->second.size();
		}

		std::vector<PacketType> ManagedSocket::typesPullable()
		{
			std::vector<PacketType> pTypes;
			std::unique_lock<std::mutex> lock(m_mtxRecvQueue);
			
			for (auto& it : m_recvQueue)
			{
				if (it.second.size() > 0)
					pTypes.push_back(it.first);
			}

			return pTypes;
		}

		void ManagedSocket::wait(PacketID packetID)
		{
			std::unique_lock<std::mutex> lock(m_mtxPacketIDBeingSent);

			m_sentNotify.wait(lock, [this, packetID](){ return packetID < m_currPacketIDBeingSent; });
		}

		void ManagedSocket::clear()
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

		void ManagedSocket::setSentCallback(PacketType pType, PacketSentCallback cb, void* pParam)
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

		void ManagedSocket::setRecvCallback(PacketType pType, PacketRecvCallback cb, void* pParam)
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

		bool ManagedSocket::callSentCallback(const Packet& pack, bool success)
		{
			setCurrentPacketBeingSent(m_currPacketIDBeingSent + 1);

			std::unique_lock<std::mutex> lock(m_mtxSentCallbacks);

			auto iterator = m_sentCallbacks.find(pack.header.packetType);
			if (iterator == m_sentCallbacks.end())
				return false;

			m_callbackPool.pushJob(std::bind(iterator->second.callback, pack.header.packetID, success, iterator->second.pParam));
			return true;
		}

		bool ManagedSocket::callRecvCallback(Packet& pack, bool success)
		{
			std::unique_lock<std::mutex> lock(m_mtxRecvCallbacks);

			auto iterator = m_recvCallbacks.find(pack.header.packetType);
			if (iterator == m_recvCallbacks.end())
				return false;

			m_callbackPool.pushJob(std::bind(iterator->second.callback, pack, success, iterator->second.pParam));
			return true;
		}

		void ManagedSocket::sendJobEncrypt(Packet packet)
		{
			m_currPacketIDBeingSent = packet.header.packetID;

			if (m_sock->writeSecure(&packet.header, sizeof(PacketHeader), false) < sizeof(PacketHeader))
			{
				callSentCallback(packet, false);
				return;
			}

			if (packet.buffer)
			{
				if (m_sock->writeSecure(packet.buffer) < packet.buffer->size())
				{
					callSentCallback(packet, false);
					return;
				}
			}
			callSentCallback(packet, true);
		}

		void ManagedSocket::sendJobNoEncrypt(Packet packet)
		{
			m_currPacketIDBeingSent = packet.header.packetID;

			if (m_sock->writeSecure(&packet.header, sizeof(PacketHeader), false) < sizeof(PacketHeader))
			{
				callSentCallback(packet, false);
				return;
			}

			if (packet.buffer)
			{
				if (m_sock->writeRaw(packet.buffer->data(), packet.buffer->size()) < packet.buffer->size())
				{
					callSentCallback(packet, false);
					return;
				}
			}
			callSentCallback(packet, true);
		}

		void ManagedSocket::makeSendableJob(Packet packet)
		{
			if (packet.buffer)
			{
				uint64_t newSize = crypto::aes::encryptThreaded(
					packet.buffer->data(),
					packet.buffer->size(),
					packet.buffer->data(),
					m_sock->getAESKey(),
					true,
					m_pCryptThreadPool->size(),
					m_pCryptThreadPool
				);
				packet.buffer->resize(newSize);
			}

			m_sendPool.pushJob(std::bind(&ManagedSocket::sendJobNoEncrypt, this, packet));
		}

		void ManagedSocket::recvJobDecrypt()
		{
			Packet pack;

			if (!m_sock->isConnected())
				goto NextIteration;

			if (m_sock->readSecure(&pack.header, sizeof(PacketHeader)) < sizeof(PacketHeader))
				goto NextIteration;

			if (pack.header.packetSize > 0)
			{
				pack.buffer = std::make_shared<PacketBuffer>(pack.header.packetSize); // TODO: Aquire buffer from pool

				if (m_sock->readSecure(pack.buffer) < pack.buffer->size())
				{
					callRecvCallback(pack, false);
					goto NextIteration;
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
			}

		NextIteration:
			if (m_sock->isConnected())
				pushRecvJob();
			m_recvNotify.notify_all();
		}

		void ManagedSocket::recvJobNoDecrypt()
		{
			Packet pack;

			if (!m_sock->isConnected())
				goto NextIteration;

			if (m_sock->readSecure(&pack.header, sizeof(pack.header)) < sizeof(pack.header))
				goto NextIteration;

			if (pack.header.packetSize > 0)
			{
				pack.buffer = std::make_shared<PacketBuffer>(pack.header.packetSize); // TODO: Aquire buffer from pool

				uint64_t paddedSize = crypto::aes::paddedSize(pack.buffer->size());
				if (m_sock->readRaw(pack.buffer->data(), paddedSize) < paddedSize)
				{
					callRecvCallback(pack, false);
					goto NextIteration;
				}
			}

			m_pCryptPool->pushJob(std::bind(&ManagedSocket::makePullableJob, this, pack));

		NextIteration:
			if (m_sock->isConnected())
				pushRecvJob();
			m_recvNotify.notify_all();
		}

		void ManagedSocket::makePullableJob(Packet packet)
		{
			if (packet.buffer)
			{
				crypto::aes::decryptThreaded(
					packet.buffer->data(),
					packet.buffer->size(),
					packet.buffer->data(),
					m_sock->getAESKey(),
					true,
					m_pCryptThreadPool->size(),
					m_pCryptThreadPool
				);
			}

			if (!callRecvCallback(packet, true))
			{
				{
					std::unique_lock<std::mutex> lock(m_mtxRecvQueue);

					auto typeIterator = m_recvQueue.find(packet.header.packetType);
					if (typeIterator == m_recvQueue.end())
						typeIterator = m_recvQueue.emplace(packet.header.packetType, std::queue<Packet>()).first;

					if (packet.header.flags & FLAG_PH_REMOVE_PREVIOUS)
					{
						while (!typeIterator->second.empty())
							typeIterator->second.pop();
					}
					typeIterator->second.push(packet);

					m_recvAvail = true;
				}
			}

			m_recvNotify.notify_all();
		}

		void ManagedSocket::pushRecvJob()
		{
			if (m_pCryptThreadPool)
				m_recvPool.pushJob(std::bind(&ManagedSocket::recvJobNoDecrypt, this));
			else
				m_recvPool.pushJob(std::bind(&ManagedSocket::recvJobDecrypt, this));
		}

		void ManagedSocket::setCurrentPacketBeingSent(PacketID pID)
		{
			{
				std::unique_lock<std::mutex> lock(m_mtxPacketIDBeingSent);
				m_currPacketIDBeingSent = pID;
			}
			m_sentNotify.notify_all();
		}
	} // namespace net
} // namespace EHSN