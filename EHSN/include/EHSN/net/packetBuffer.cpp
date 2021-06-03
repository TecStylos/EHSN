#include "packetBuffer.h"

#include <memory>

#include "packetQueue.h"

namespace EHSN {
	namespace net {

		PacketBuffer::PacketBuffer()
		{
			m_pBufferInfo = new BufferInfo;
			++m_pBufferInfo->refCount;
		}

		PacketBuffer::PacketBuffer(uint64_t size)
			: PacketBuffer()
		{
			createBuffer(size);
		}

		PacketBuffer::PacketBuffer(uint64_t size, PacketQueue* pQueue)
			: PacketBuffer(size)
		{
			m_pBufferInfo->pQueue = pQueue;
			if (pQueue)
				setReturnToQueue(true);
		}

		PacketBuffer::PacketBuffer(const PacketBuffer& other)
		{
			m_pBufferInfo = other.m_pBufferInfo;
			++m_pBufferInfo->refCount;
		}

		PacketBuffer::PacketBuffer(PacketBuffer&& other) noexcept
		{
			m_pBufferInfo = other.m_pBufferInfo;
			other.m_pBufferInfo = nullptr;
		}

		PacketBuffer& PacketBuffer::operator=(const PacketBuffer& other)
		{
			removeReference();

			m_pBufferInfo = other.m_pBufferInfo;
			++m_pBufferInfo->refCount;

			return *this;
		}

		PacketBuffer& PacketBuffer::operator=(PacketBuffer&& other) noexcept
		{
			removeReference();

			m_pBufferInfo = other.m_pBufferInfo;
			other.m_pBufferInfo = nullptr;

			return *this;
		}

		PacketBuffer::~PacketBuffer()
		{
			removeReference();
		}

		void* PacketBuffer::data() const
		{
			return m_pBufferInfo->buffer;
		}

		uint64_t PacketBuffer::size() const
		{
			return m_pBufferInfo->size;
		}

		uint64_t PacketBuffer::reserved() const
		{
			return m_pBufferInfo->nReserved;
		}

		void PacketBuffer::read(void* dest, uint64_t size, uint64_t offset) const
		{
			memcpy(dest, (char*)m_pBufferInfo->buffer + offset, size);
		}

		void PacketBuffer::write(const void* src, uint64_t size, uint64_t offset)
		{
			memcpy((char*)m_pBufferInfo->buffer + offset, src, size);
		}

		void PacketBuffer::resize(uint64_t newSize)
		{
			if (newSize <= m_pBufferInfo->nReserved)
				m_pBufferInfo->size = newSize;
			else
				createBuffer(newSize);
		}

		void PacketBuffer::setReturnToQueue(bool returnToQueue)
		{
			m_pBufferInfo->returnToQueue = returnToQueue;
		}

		void PacketBuffer::deleteBuffer()
		{
			if (m_pBufferInfo->buffer != nullptr)
			{
				delete[](char*)m_pBufferInfo->buffer;
				m_pBufferInfo->buffer = nullptr;
			}
			m_pBufferInfo->size = 0;
			m_pBufferInfo->nReserved = 0;
		}

		void PacketBuffer::createBuffer(uint64_t size)
		{
			deleteBuffer();

			uint64_t paddedSize = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
			paddedSize *= CHUNK_SIZE;

			m_pBufferInfo->buffer = new char[paddedSize];
			m_pBufferInfo->size = size;
			m_pBufferInfo->nReserved = paddedSize;
		}

		void PacketBuffer::removeReference()
		{
			if (m_pBufferInfo &&
				--m_pBufferInfo->refCount == 0)
			{
				if (m_pBufferInfo->returnToQueue && m_pBufferInfo->pQueue)
				{
					m_pBufferInfo->pQueue->releaseBuffer(*this);
				}
				else
				{
					deleteBuffer();
					delete m_pBufferInfo;
				}
				m_pBufferInfo = nullptr;
			}
		}

		PacketBuffer::operator bool() const
		{
			return m_pBufferInfo->buffer != nullptr;
		}

	} // namespace net
} // namespace EHSN