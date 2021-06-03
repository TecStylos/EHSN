#ifndef PACKETS_H
#define PACKETS_H

#include <cstdint>

namespace EHSN {
	namespace net {

		namespace packets {
			#pragma pack(push, 1)

			union IPAddress
			{
				uint32_t uint = 0;
				unsigned char bytes[4];
			};

			struct HandshakeInfo
			{
				const char host[16] = "TECSTYLOS-NET";
				uint16_t aesKeySize;
				uint16_t aesKeyEchoSize;
				uint64_t hostLocalTime;
				IPAddress clientIP;
			};
			struct HandshakeReply
			{
				const char host[16] = "TECSTYLOS-NET";
				uint64_t hostLocalTime;
			};

			#pragma pack(pop)
		} // namespace packets
	} // namespace net
} // namespace EHSN

#endif // PACKETS_H