#include "packetBuffer.h"

#include <memory>

#include "packetQueue.h"

namespace EHSN {
	namespace net {

		PacketBuffer::PacketBuffer()
			: PacketBuffer(1)
		{
		}

		PacketBuffer::PacketBuffer(uint64_t size)
		{
			createBuffer(size);
		}

		PacketBuffer::PacketBuffer(const PacketBuffer& other)
		{
			createBuffer(other.m_size);
			write(other.m_buffer, m_size);
		}

		PacketBuffer::~PacketBuffer()
		{
			deleteBuffer();
		}

		void* PacketBuffer::data() const
		{
			return m_buffer;
		}

		uint64_t PacketBuffer::size() const
		{
			return m_size;
		}

		uint64_t PacketBuffer::reserved() const
		{
			return m_nReserved;
		}

		void PacketBuffer::read(void* dest, uint64_t size, uint64_t offset) const
		{
			memcpy(dest, m_buffer + offset, size);
		}

		void PacketBuffer::write(const void* src, uint64_t size, uint64_t offset)
		{
			memcpy(m_buffer + offset, src, size);
		}

		void PacketBuffer::resize(uint64_t newSize)
		{
			if (newSize <= m_nReserved)
				m_size = newSize;
			else
				createBuffer(newSize);
		}

		void PacketBuffer::createBuffer(uint64_t size)
		{
			deleteBuffer();

			uint64_t paddedSize = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
			paddedSize *= CHUNK_SIZE;

			m_buffer = new uint8_t[paddedSize];
			m_size = size;
			m_nReserved = paddedSize;
		}

		void PacketBuffer::deleteBuffer()
		{
			if (m_buffer != nullptr)
			{
				delete[]m_buffer;
				m_buffer = nullptr;
			}
			m_size = 0;
			m_nReserved = 0;
		}

	} // namespace net
} // namespace EHSN