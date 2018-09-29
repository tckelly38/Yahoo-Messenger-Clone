all: messenger_server messenger_client

messenger_server: ../src/messenger_server.cpp
	g++ -std=c++11 -o messenger_server -I../src ../src/messenger_server.cpp

messenger_client: ../src/messenger_client.cpp
	g++ -std=c++11 -pthread -o messenger_client -I../src ../src/messenger_client.cpp

clean:
	rm messenger_server messenger_client
