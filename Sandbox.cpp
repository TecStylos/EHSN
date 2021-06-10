#include "EHSN.h"

#include <iostream>

#define CLIENT_THREADS_PER_SOCKET 8
#define SERVER_THREADS_PER_SOCKET 4

std::vector<std::string> splitCommand(const std::string& command) {
	std::vector<std::string> commandParts;

	bool isQuoted = false;

	std::string currPart;

	for (char c : command)
	{
		switch (c)
		{
		case ' ':
		{
			if (!currPart.empty())
			{
				if (isQuoted)
				{
					currPart.push_back(c);
				}
				else
				{
					commandParts.push_back(currPart);
					currPart.clear();
				}
			}
			break;
		}
		case '"':
		{
			if (!currPart.empty())
			{
				commandParts.push_back(currPart);
				currPart.clear();
			}
			isQuoted = !isQuoted;
			break;
		}
		default:
		{
			currPart.push_back(c);
			break;
		}
		}
	}

	if (!currPart.empty())
		commandParts.push_back(currPart);

	return commandParts;
}

enum CUSTOM_PACKET_TYPES : EHSN::net::PacketType {
	CPT_RAW_DATA = EHSN::net::SPT_FIRST_FREE_PACKET_TYPE,
};

void sessionFunc(EHSN::Ref<EHSN::net::SecSocket> sock, void* pParam) {
	EHSN::net::ManagedSocket queue(sock, SERVER_THREADS_PER_SOCKET);

	queue.setRecvCallback(
		EHSN::net::SPT_PING,
		[](EHSN::net::Packet pack, uint64_t nBytesReceived, void* pParam)
		{
			if (nBytesReceived < pack.header.packetSize)
				return;

			std::cout << "    Got ping request!" << std::endl;
			auto& queue = *(EHSN::net::ManagedSocket*)pParam;
			pack.header.packetType = EHSN::net::SPT_PING_REPLY;
			queue.push(pack);
		},
		&queue
			);

	queue.setRecvCallback(
		CPT_RAW_DATA,
		[](EHSN::net::Packet pack, uint64_t nBytesReceived, void* pParam)
		{
			if (nBytesReceived < pack.header.packetSize)
				return;

			std::cout << "    Got raw data!" << std::endl;
		},
		nullptr
			);
	
	uint64_t nWrittenLast = 0;
	uint64_t nReadLast = 0;
	bool sentAliveRequest = false;

	while (sock->isConnected())
	{
		std::this_thread::sleep_for(std::chrono::seconds(15));

		uint64_t nWrittenNew = sock->getDataMetrics().nWritten();
		uint64_t nReadNew = sock->getDataMetrics().nRead();

		if (nWrittenNew == nWrittenLast && nReadNew == nReadLast)
		{
			if (sentAliveRequest)
			{
				sentAliveRequest = false;
				if (queue.nPullable(EHSN::net::SPT_KEEP_ALIVE_REPLY))
				{
					queue.pull(EHSN::net::SPT_KEEP_ALIVE_REPLY);
				}
				else
					queue.disconnect();
				continue;
			}

			queue.push(EHSN::net::SPT_KEEP_ALIVE_REQUEST, EHSN::net::FLAG_PH_NONE, nullptr);
			sentAliveRequest = true;
		}

		if (queue.nPullable(EHSN::net::SPT_KEEP_ALIVE_REPLY))
		{
			queue.pull(EHSN::net::SPT_KEEP_ALIVE_REPLY);
		}

		nWrittenLast = nWrittenNew;
		nReadLast = nReadNew;
		continue;
	}

	std::cout << "  Lost connection to client!" << std::endl;
}

int main(int argc, const char* argv[], const char* env[]) {

	bool runServer = true;
	for (int i = 0; i < argc; ++i)
	{
		std::string arg = argv[i];

		if (arg == "--server")
		{
			runServer = true;
		}

		if (arg == "--client")
		{
			runServer = false;
		}
	}

	bool noDelay = true;

	if (runServer)
	{
		std::cout << "Creating secAcceptor..." << std::endl;
		EHSN::net::SecAcceptor acceptor("10000", sessionFunc, nullptr, nullptr);
		while (true)
		{
			std::cout << "Waiting for connection..." << std::endl;
			acceptor.newSession(noDelay, 0);
			std::cout << "  New connection accepted!" << std::endl;
		}

		return 0;
	}

	std::string host = "tecstylos.ddns.net";
	std::string port = "10000";

	EHSN::net::ManagedSocket queue(std::make_shared<EHSN::net::SecSocket>(EHSN::crypto::defaultRDG, 0), CLIENT_THREADS_PER_SOCKET);

	while (true)
	{
		std::string command;
		std::cout << " >>> ";
		std::getline(std::cin, command);

		std::vector<std::string> cmdParts = splitCommand(command);
		auto it = cmdParts.begin();
		if (it == cmdParts.end())
			continue;

		if (*it == "help")
		{
			std::cout << "   Currently no help available." << std::endl;
		}
		else if (*it == "host")
		{
			++it;
			if (it == cmdParts.end())
				std::cout << "   Current host: " << host << std::endl;
			else
			{
				host = *it;
				std::cout << "   Set host to: " << host << std::endl;
			}
		}
		else if (*it == "port")
		{
			++it;
			if (it == cmdParts.end())
				std::cout << "   Current port: " << port << std::endl;
			else
			{
				port = *it;
				std::cout << "   Set port to: " << port << std::endl;
			}
		}
		else if (*it == "noDelay")
		{
			++it;
			if (it == cmdParts.end())
				std::cout << "   Current value: " << (noDelay ? "on" : "off") << std::endl;
			else
			{
				noDelay = *it == "on";
				std::cout << "   Set noDelay to: " << (noDelay ? "on" : "off") << std::endl;
			}
		}
		else if (*it == "connect")
		{
			std::cout << "   Connecting to: " << host << ":" << port << "..." << std::endl;
			if (queue.connect(host, port, noDelay))
				std::cout << "    Connected to host!" << std::endl;
			else
				std::cout << " ERROR" << std::endl;
		}
		else if (*it == "disconnect")
		{
			std::cout << "   Disconnecting..." << std::endl;
			queue.disconnect();
			std::cout << "   Disconnected from host!" << std::endl;
		}
		else if (*it == "benchmark")
		{
			++it;
			if (it == cmdParts.end())
			{
				std::cout << "   Missing arguments!" << std::endl;
				continue;
			}

			if (*it == "data")
			{
				std::cout << "    Running data test..." << std::endl;

				constexpr uint64_t packetSize = 25_MB;
				constexpr uint64_t nPackets = 10;

				std::cout << "     Sending packets..." << std::endl;

				std::vector<EHSN::Ref<EHSN::net::PacketBuffer>> buffers;
				buffers.resize(nPackets);
				for (uint64_t i = 0; i < nPackets; ++i)
				{
					buffers[i] = std::make_shared<EHSN::net::PacketBuffer>(packetSize);
					buffers[i]->write(i);
				}

				uint64_t begin = CURR_TIME_NS();

				EHSN::net::PacketID lastPacketID;
				for (uint64_t i = 0; i < nPackets; ++i)
					queue.push(CPT_RAW_DATA, EHSN::net::FLAG_PH_NONE, buffers[i]);
				{
					auto pingBuffer = std::make_shared<EHSN::net::PacketBuffer>(sizeof(uint64_t));
					uint64_t start = CURR_TIME_NS();
					pingBuffer->write(start);
					queue.push(EHSN::net::SPT_PING, EHSN::net::FLAG_PH_NONE, pingBuffer);
					queue.pull(EHSN::net::SPT_PING_REPLY);
				}

				uint64_t end = CURR_TIME_NS();

				uint64_t timeSum = end - begin;

				float timeInSec = timeSum / 1000.0f / 1000.0f / 1000.0f;

				float sentData = (float)(nPackets * packetSize) / 1000.0f / 1000.0f;
				float secPerPacket = timeInSec / (float)nPackets;
				float dataPerSec = sentData / timeInSec * 8;

				std::cout << "   Data sent:       " << sentData << " MB" << std::endl;
				std::cout << "   Packets sent:    " << nPackets << std::endl;
				std::cout << "   Time:            " << timeInSec << " sec" << std::endl;
				std::cout << "   Time per packet: " << secPerPacket << " sec" << std::endl;
				std::cout << "   Data/Time:       " << dataPerSec << " Mbps" << std::endl;

				std::cout << "   Raw write speed: " << (queue.getSock()->getDataMetrics().avgWriteSpeed() / 1000.0f / 1000.0f) << " MBps" << std::endl;
			}
			else if (*it == "ping")
			{
				uint64_t nPings = 10;

				struct LambdaStruct
				{
					std::queue<uint64_t> pingQueue;
					bool gotPing = false;
					std::mutex mtx;
					std::condition_variable conVar;
				} st;

				queue.setRecvCallback
				(
					EHSN::net::SPT_PING_REPLY,
					[](EHSN::net::Packet pack, uint64_t nBytesReceived, void* pParam)
					{
						if (nBytesReceived < pack.header.packetSize)
							return;

						auto& st = *(LambdaStruct*)pParam;
						uint64_t end = CURR_TIME_NS();
						uint64_t start;
						pack.buffer->read(start);
						st.pingQueue.push(end - start);

						{
							std::unique_lock<std::mutex> lock(st.mtx);
							st.gotPing = true;
						}
						st.conVar.notify_one();
					},
					&st
				);

				for (int i = 0; i < nPings; ++i)
				{
					auto buffer  = std::make_shared<EHSN::net::PacketBuffer>(sizeof(uint64_t));
					uint64_t start = CURR_TIME_NS();
					buffer->write(start);
					queue.push(EHSN::net::SPT_PING, EHSN::net::FLAG_PH_NONE, buffer);
					EHSN::net::PacketHeader header;

					std::unique_lock<std::mutex> lock(st.mtx);
					st.conVar.wait(lock, [&st] { return st.gotPing; });
					st.gotPing = false;
				}

				uint64_t pingSum = 0;
				while (!st.pingQueue.empty())
				{
					pingSum += st.pingQueue.front();
					st.pingQueue.pop();
				}

				queue.setRecvCallback(EHSN::net::SPT_PING_REPLY, nullptr, nullptr);

				std::cout << "   Number of collected pings: " << nPings << std::endl;
				std::cout << "   Average ping: " << (pingSum / nPings) << " ms" << std::endl;
			}
			else
			{
				std::cout << "   Unknown arguments!" << std::endl;
			}
		}
		else if (*it == "metrics")
		{
			auto& metrics = queue.getSock()->getDataMetrics();
			std::cout << "   Read:    " << metrics.nRead() << " bytes" << std::endl;
			std::cout << "   Written: " << metrics.nWritten() << " bytes" << std::endl;
		}
		else if (*it == "resetMetrics")
		{
			queue.getSock()->resetDataMetrics();
			std::cout << "  Metrics reset." << std::endl;
		}
		else if (*it == "exit")
		{
			std::cout << "Exiting..." << std::endl;
			break;
		}
		else
		{
			std::cout << "   Unknown command." << std::endl;
		}
	}

	return 0;
}