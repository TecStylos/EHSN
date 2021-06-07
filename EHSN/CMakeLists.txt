# CMakeList.txt : CMake project for EHSN, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Project source files
add_library (
	EHSN
	"include/EHSN/crypto/aes/aesAlgorithm.cpp"
	"include/EHSN/crypto/aes/aesKey.cpp"
	"include/EHSN/crypto/rsa/rsaAlgorithm.cpp"
	"include/EHSN/crypto/rsa/rsaKey.cpp"
	"include/EHSN/net/ioContext.cpp"
	"include/EHSN/net/packetBuffer.cpp"
	"include/EHSN/net/managedSocket.cpp"
	"include/EHSN/net/secAcceptor.cpp"
	"include/EHSN/net/secSocket.cpp"
	"include/EHSN/ThreadPool.cpp"
)

# Cross-Platform Include Directories
target_include_directories (
	EHSN PUBLIC
	"include"
)

# Platform dependend
if (UNIX) # Unix specific

	# OpenSSL
	set (OPENSSL_USE_STATIC_LIBS TRUE)
	find_package (OpenSSL REQUIRED)
	target_link_libraries(EHSN PRIVATE OpenSSL::SSL)

	# pthread library
	set (THREADS_PREFER_PTHREAD_FLAG ON)
	find_package (Threads REQUIRED)
	target_link_libraries(EHSN PRIVATE Threads::Threads)

	target_link_libraries(EHSN PRIVATE atomic)

	# Include directories
	target_include_directories (
		EHSN PUBLIC
		"/usr/local/src/openssl-1.1.1j/include"
	)
elseif (WIN32) # Windows specific

	# OpenSSL
	set (OPENSSL_USE_STATIC_LIBS TRUE)
	find_package(OpenSSL REQUIRED)
	target_link_libraries(EHSN PUBLIC OpenSSL::SSL crypt32)

	# Include directories
	target_include_directories (
		EHSN PUBLIC
		"C:\\dev\\vendor-libs\\openssl\\include"
		"vendor/asio/asio/include"
	)

	# Library directories
	target_link_directories (
		EHSN PUBLIC 
		"C:\\dev\\vendor-libs\\openssl"
	)
endif ()

set_property(TARGET PROPERTY CMAKE_CXX_STANDARD 17)