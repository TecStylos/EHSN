#include "EHSN.h"

#include <iostream>

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
	}

	if (!currPart.empty())
		commandParts.push_back(currPart);

	return commandParts;
}

#define CURR_TIME_MS() std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()).time_since_epoch().count()

enum CUSTOM_PACKET_TYPES : EHSN::net::PacketType {
	CPT_RAW_DATA = EHSN::net::SPT_FIRST_FREE_PACKET_TYPE,
};

void sessionFunc(EHSN::Ref<EHSN::net::SecSocket> sock, void* pParam) {
	EHSN::net::PacketQueue queue(sock);

	queue.setRecvCallback(
		EHSN::net::SPT_PING,
		[](EHSN::net::Packet pack, bool success, void* pParam)
		{
			auto& queue = *(EHSN::net::PacketQueue*)pParam;
			pack.header.packetType = EHSN::net::SPT_PING_REPLY;
			queue.push(pack.header, pack.buffer);
		},
		&queue
			);
	
	while (sock->isConnected())
	{
		std::cout << "  Pulling buffer..." << std::endl;
		EHSN::net::Packet pack = queue.pull(CPT_RAW_DATA);
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
			acceptor.newSession(noDelay);
			std::cout << "  New connection accepted!" << std::endl;
		}
	}

	std::string host = "tecstylos.ddns.net";
	std::string port = "10000";

	EHSN::net::PacketQueue queue(std::make_shared<EHSN::net::SecSocket>(EHSN::crypto::defaultRDG, std::thread::hardware_concurrency() / 2));

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

				constexpr uint64_t packetSize = 100 * 1000 * 1000;
				uint64_t timeSum = 0;
				uint64_t nPackets = 0;

				std::cout << "     Sending packets..." << std::endl;

				for (int i = 0; i < 10; ++i)
				{
					auto buffer = std::make_shared<EHSN::net::PacketBuffer>(packetSize);
					buffer->write(i);

					uint64_t begin = CURR_TIME_MS();
					queue.wait(queue.push(CPT_RAW_DATA, EHSN::net::FLAG_PH_NONE, buffer));
					uint64_t end = CURR_TIME_MS();

					timeSum += end - begin;
					++nPackets;
				}

				float sentData = (float)(nPackets * packetSize) / 1000.0f / 1000.0f;
				float timePerPacket = (float)timeSum / (float)nPackets;
				float dataPerTime = sentData / timeSum * 1000.0f * 8;

				std::cout << "   Data sent:       " << sentData << " MB" << std::endl;
				std::cout << "   Packets sent:    " << nPackets << std::endl;
				std::cout << "   Time:            " << (timeSum) << " ms" << std::endl;
				std::cout << "   Time per packet: " << timePerPacket << " ms" << std::endl;
				std::cout << "   Data/Time:       " << dataPerTime << " Mbps" << std::endl;
			}
			else if (*it == "ping")
			{
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
					[](EHSN::net::Packet pack, bool success, void* pParam)
					{
						auto& st = *(LambdaStruct*)pParam;
						uint64_t end = CURR_TIME_MS();
						st.pingQueue.push(end - *(uint64_t*)pack.buffer->data());

						{
							std::unique_lock<std::mutex> lock(st.mtx);
							st.gotPing = true;
						}
						st.conVar.notify_one();
					},
					&st
				);

				for (int i = 0; i < 10; ++i)
				{
					auto buffer  = std::make_shared<EHSN::net::PacketBuffer>(sizeof(uint64_t));
					uint64_t start = CURR_TIME_MS();
					buffer->write(start);
					queue.push(EHSN::net::SPT_PING, EHSN::net::FLAG_PH_NONE, buffer);
					EHSN::net::PacketHeader header;

					std::unique_lock<std::mutex> lock(st.mtx);
					st.conVar.wait(lock, [&st] { return st.gotPing; });
					st.gotPing = false;
				}

				uint64_t pingSum = 0;
				uint64_t nPings = 0;
				while (!st.pingQueue.empty())
				{
					++nPings;
					pingSum += st.pingQueue.front();
					st.pingQueue.pop();
				}

				queue.setRecvCallback(EHSN::net::SPT_PING, nullptr, nullptr);

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