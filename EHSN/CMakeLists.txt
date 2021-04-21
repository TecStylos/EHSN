# CMakeList.txt : CMake project for EHSN, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add include directories
add_library (
	EHSN
	"include/EHSN.h"
	"include/EHSN/crypto.h"
	"include/EHSN/net.h"
	"include/EHSN/Reference.h"
	"include/EHSN/crypto/aes.h"
	"include/EHSN/crypto/rsa.h"
	"include/EHSN/crypto/aes/aesAlgorithm.h"
	"include/EHSN/crypto/aes/aesAlgorithm.cpp"
	"include/EHSN/crypto/aes/aesKey.h"
	"include/EHSN/crypto/aes/aesKey.cpp"
	"include/EHSN/crypto/aes/ossl_aes_include.h"
	"include/EHSN/crypto/rsa/ossl_rsa_include.h"
	"include/EHSN/crypto/rsa/rsaAlgorithm.h"
	"include/EHSN/crypto/rsa/rsaAlgorithm.cpp"
	"include/EHSN/crypto/rsa/rsaKey.h"
	"include/EHSN/crypto/rsa/rsaKey.cpp"
	"include/EHSN/net/ioContext.h"
	"include/EHSN/net/ioContext.cpp"
	"include/EHSN/net/packetBuffer.h"
	"include/EHSN/net/packetBuffer.cpp"
	"include/EHSN/net/packetQueue.h"
	"include/EHSN/net/packetQueue.cpp"
	"include/EHSN/net/packets.h"
	"include/EHSN/net/secAcceptor.h"
	"include/EHSN/net/secAcceptor.cpp"
	"include/EHSN/net/secSocket.h"
	"include/EHSN/net/secSocket.cpp"
)

target_include_directories (
	EHSN PUBLIC
	"include"
)

if (UNIX)
	target_include_directories (
		EHSN PUBLIC
		"/usr/local/src/openssl-1.1.1j/include"
	)

	set (THREADS_PREFER_PTHREAD_FLAG ON)
	find_package (Threads REQUIRED)
	target_link_libraries(EHSN PRIVATE Threads::Threads)
	
	find_package (OpenSSL REQUIRED)
	target_link_libraries(EHSN PRIVATE OpenSSL::SSL)

	target_compile_options (
		EHSN PUBLIC 
		"-O2"
		"-march=native"
		"-mtune=native"
	)
elseif (WIN32)
	target_include_directories (
		EHSN PUBLIC
		"C:\\dev\\vendor-libs\\openssl\\include"
		"C:\\dev\\vendor-libs\\asio-1.18.1\\include"
	)
	target_link_directories (
		EHSN PUBLIC 
		"C:\\dev\\vendor-libs\\openssl\\lib"
	)
endif ()

set_property(TARGET PROPERTY CMAKE_CXX_STANDARD 17)

# TODO: Add tests and install targets if needed.
