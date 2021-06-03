#ifndef PACKETBUFFER_H
#define PACKETBUFFER_H

#include <cstdint>

namespace EHSN {
	namespace net {

		constexpr uint64_t CHUNK_SIZE = 2048;

		class PacketQueue;

		class PacketBuffer
		{
		public:
			PacketBuffer();
			/*
			* Constructor of PacketBuffer
			*
			* @param size Size of the new buffer being allocated.
			*/
			PacketBuffer(uint64_t size);
			PacketBuffer(uint64_t size, PacketQueue* pQueue);
		public:
			PacketBuffer(const PacketBuffer& other);
			PacketBuffer(PacketBuffer&& other) noexcept;
			PacketBuffer& operator=(const PacketBuffer& other);
			PacketBuffer& operator=(PacketBuffer&& other) noexcept;
		public:
			~PacketBuffer();
		public:
			/*
			* Get a pointer to the data.
			*
			* @returns Pointer to the data stored.
			*/
			void* data() const;
			/*
			* Get the number of bytes being used.
			*
			* @returns Size of the buffer in use.
			*/
			uint64_t size() const;
			/*
			* Get the number of bytes reserved for the buffer.
			*
			* @returns Reserved size of the buffer.
			*/
			uint64_t reserved() const;
			/*
			* Read data from the packet buffer.
			*
			* @param dest The buffer where to write the data to.
			* @param size The number of bytes to read from the packet buffer.
			* @param offset The offset in the packet buffer of the first byte being read.
			*/
			void read(void* dest, uint64_t size, uint64_t offset = 0) const;
			/*
			* Read data from the packet buffer.
			*
			* @param obj The object where to write the data to.
			* @param offset The offset in the packet buffer of the first byte being read.
			*/
			template <typename T>
			void read(T& obj, uint64_t offset = 0) const;
			/*
			* Write data to the packet buffer.
			*
			* @param src The buffer where to read the data from.
			* @param size The number of bytes to write to the packet buffer.
			* @param offset The offset in the packet buffer of the first byte being written.
			*/
			void write(const void* src, uint64_t size, uint64_t offset = 0);
			/*
			* Write data to the packet buffer.
			*
			* @param obj The object to write to the buffer.
			* @param offset The offset in the packet buffer of the first byte being written.
			*/
			template <typename T>
			void write(const T& obj, uint64_t offset = 0);
		public:
			/*
			* Resize the buffer.
			*
			* If newSize is bigger than the reserved size, the old buffer gets deleted and a new one created.
			* Otherwise buffer remains the same but 'size' will be changed.
			* The new buffer may not hold the data of the old buffer!
			*
			* The new reserved size of the buffer may be bigger than newSize!
			*
			* @param newSize New size of the buffer.
			*/
			void resize(uint64_t newSize);
		public:
			/*
			* Set whether the buffer should be returned to the queue when the last reference gets destroyed.
			*
			* @param returnTuQueue Set to true if the buffer should be returned to the queue when the last reference gets destroyed. Otherwise false.
			*/
			void setReturnToQueue(bool returnToQueue);
		private:
			/*
			* Delete the current buffer.
			*
			* If no buffer is allocated nothing happens.
			*/
			void deleteBuffer();
			/*
			* Delete the old buffer and creates a new one.
			*
			* The size of the buffer always gets padded to the next multiple of CHUNK_SIZE.
			*
			* @param size Size of the new buffer.
			*/
			void createBuffer(uint64_t size);
			/*
			* Remove the reference to the underlying buffer and delete it if necessary.
			*/
			void removeReference();
		public:
			operator bool() const;
		private:
			struct BufferInfo
			{
				void* buffer = nullptr;
				uint64_t size = 0;
				uint64_t nReserved = 0;

				PacketQueue* pQueue = nullptr;
				bool returnToQueue = false;

				uint64_t refCount = 0;
			} *m_pBufferInfo;
		};

		template<typename T>
		inline void PacketBuffer::read(T& obj, uint64_t offset) const
		{
			read(&obj, sizeof(T), offset);
		}

		template<typename T>
		inline void PacketBuffer::write(const T& obj, uint64_t offset)
		{
			write(&obj, sizeof(T), offset);
		}

	} // namespace net
} // namespace EHSN

#endif // PACKETBUFFER_H