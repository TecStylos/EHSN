#pragma once

namespace EHSN {
	namespace crypto
	{
		/*
		* Fill a buffer with random data.
		*
		* @param buffer Buffer to be filled with random data.
		* @param nBytes Number of bytes to generate.
		*/
		typedef void(*RandomDataGenerator)(char*, uint64_t);

		/*
		* Default implementation for RandomDataGenerator.
		*/
		inline void defaultRDG(char* buffer, uint64_t nBytes)
		{
			for (uint64_t i = 0; i < nBytes; ++i)
				buffer[i] = rand() % 256;
		}
	}
}