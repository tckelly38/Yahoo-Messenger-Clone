all: messenger_server messenger_client

messenger_server: messenger_server.cpp
	g++ -std=c++11 -o messenger_server messenger_server.cpp

messenger_client: messenger_client.cpp
	g++ -std=c++11 -pthread -o messenger_client messenger_client.cpp

clean:
	rm messenger_server messenger_client
