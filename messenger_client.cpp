#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include <pthread.h>
#include <signal.h>

#define LISTENING_PORT "5100"
using namespace std;
#define MAXDATASIZE 1024
typedef struct serv_t{
  string servhost;
  int servport;

}serv_t;
typedef struct friend_t{
  string hostname;
  string username;
  int socket_fd;
}friend_t;


struct FindByUSR{
  const string usr;
  FindByUSR(const string& usr): usr(usr) {}
  bool operator() (const friend_t u) const{
    return u.username == usr;
  }
};
struct FindBySOCK{
  const int sock;
  FindBySOCK(const int& sock): sock(sock) {}
  bool operator() (const friend_t u) const{
    return u.socket_fd == sock;
  }
};


vector<friend_t> onlineFriends;
char server_hostname[1024];
bool valid_login;
string my_username;
string my_ip;
pthread_mutex_t onlineFriends_mutex;
pthread_mutex_t invites_recieved_mutex;
pthread_mutex_t invites_sent_mutex;
pthread_attr_t detatch_thread_attr;
pthread_mutex_t opened_sockets_mutex;
pthread_mutex_t active_threads_mutex;
pthread_mutex_t valid_login_mutex;

vector<int> opened_sockets;
vector<pthread_t> active_threads;
vector<string> invites_recieved;
vector<string> invites_sent;
int server_socket;
void sigint_handler(int s);

void _read_in_config(serv_t& serv, const string configuration_file);
void _check_input_files(const int argc, char const* const *argv, int *status);
void *_get_in_addr(struct sockaddr *sa);
int setup_server_for_listening(int& listening_socket_fd);
void *user_input(void *args);
void *server_input(void *args);
void *friend_connections(void *args);
void *accept_connections(void* args);
int init_server(struct addrinfo *aip);
int establishConnection(const char *hostname, const char *port);
bool valid_login_condition();
int main(int argc, char *argv[]){
  int status;
  serv_t serv;
  string command;
  string username;
  string password;
  int numbytes;
  char msg_buf[MAXDATASIZE];
  valid_login = false;


  _check_input_files(argc, argv, &status);
  if(status < 0)
    exit(EXIT_FAILURE);

  string configuration_file = argv[1];
  _read_in_config(serv, configuration_file);

  /* init signal handler */
  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if(sigaction(SIGINT, &sa, NULL) == -1){
    cerr << "sigaction" << endl;
    exit(EXIT_FAILURE);
  }

  strcpy(server_hostname, serv.servhost.c_str());
  server_socket = establishConnection(server_hostname, to_string(serv.servport).c_str());
  pthread_t standard_input_thread;
  pthread_t server_input_thread;

  if(pthread_mutex_init(&onlineFriends_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_mutex_init(&invites_sent_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_mutex_init(&invites_recieved_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_mutex_init(&opened_sockets_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_mutex_init(&active_threads_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_mutex_init(&valid_login_mutex, NULL) !=0){
    cerr << "Failed to init online friend mutex" << endl;
    exit(EXIT_FAILURE);
  }
  pthread_attr_init(&detatch_thread_attr);
  pthread_attr_setdetachstate(&detatch_thread_attr, PTHREAD_CREATE_DETACHED);


  // user can send initial command (l-login, r-register, exit)
  if(pthread_create(&standard_input_thread, NULL, user_input, (void*)NULL) != 0){
    cerr << "error starting stdin thread" << endl;
    exit(EXIT_FAILURE);
  }
  if(pthread_create(&server_input_thread, NULL, server_input, (void*)NULL) != 0){
    cerr << "error starting server listener thread" << endl;
    exit(EXIT_FAILURE);
  }
  pthread_join(standard_input_thread, NULL);
  pthread_join(server_input_thread, NULL);
  return EXIT_SUCCESS;
}
void sigint_handler(int s){
  /* close all opened sockets */
  pthread_mutex_lock(&opened_sockets_mutex);
  for(int i = 0; i < opened_sockets.size(); i++){
    close(opened_sockets[i]);
  }
  opened_sockets.clear();
  pthread_mutex_unlock(&opened_sockets_mutex);
  close(server_socket);
  exit(EXIT_SUCCESS);
}
void *accept_connections(void* args){
  int &sockfd = *(int*)args;
  pthread_mutex_lock(&opened_sockets_mutex);
  opened_sockets.push_back(sockfd);
  pthread_mutex_unlock(&opened_sockets_mutex);
  socklen_t addrlen;
  struct sockaddr_storage clientaddr;
  addrlen = sizeof clientaddr;
  int newfd;
  while (true){
    if((newfd = accept(sockfd, (struct sockaddr *)&clientaddr, &addrlen)) >= 0)
    {
      pthread_t new_friend_thread;
      if (pthread_create(&new_friend_thread, &detatch_thread_attr, friend_connections, (void*)&newfd) != 0){
        cerr << "error creating friend thread from accept connections" << endl;
        exit(EXIT_FAILURE);
      }
      pthread_mutex_lock(&active_threads_mutex);
      active_threads.push_back(new_friend_thread);
      pthread_mutex_unlock(&active_threads_mutex);

    }
  }
}
void *friend_connections(void *args){
  //friend_t &frd = *(friend_t*)args;
  int &sockfd = *(int*)args;
  pthread_mutex_lock(&opened_sockets_mutex);
  opened_sockets.push_back(sockfd);
  pthread_mutex_unlock(&opened_sockets_mutex);

  char resp[1024];
  int numbytes;
  while(true){
    if((numbytes = recv(sockfd, resp, sizeof resp, 0)) > 0){
      resp[numbytes] = '\0';
      /**/
      string resp_str = resp;
      string username;
      string message;
      istringstream iss(resp_str);
      getline(iss, username, '|');
      getline(iss, message);
      cout << username << ">>" << message << endl;
    }
  }
  return NULL;
}
int establishConnection(const char *hostname, const char *port){
  int sockfd;
  char buf[256];
  struct addrinfo hints, *servinfo, *p;
  int err;
  char s[INET_ADDRSTRLEN];


  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if((err = getaddrinfo(hostname, port, &hints, &servinfo)) != 0){
    cerr << "getaddrinfo: " << gai_strerror(err) << endl;
    exit(EXIT_FAILURE);
  }
  for(p = servinfo; p != NULL; p = p->ai_next){
    if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
      continue;
    }
    if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
      close(sockfd);
      continue;
    }
    break;
  }
  if(p == NULL){
    cerr << "client: failed to connect" << endl;
    exit(EXIT_FAILURE);
  }
  inet_ntop(p->ai_family, _get_in_addr((struct sockaddr*) &p->ai_addr), s, sizeof s);
  //cout << "connecting to: " << s << endl;
  freeaddrinfo(servinfo);
  return sockfd;

}
void *server_input(void *args){
  char msg_buf[256];
  int numbytes;
  while (true){
    if ((numbytes = recv(server_socket, msg_buf, sizeof msg_buf, 0)) > 0){ // have stuff to look at
      msg_buf[numbytes] = '\0';
      string message = msg_buf;
      string code;
      istringstream iss(message);
      getline(iss, code, ' ');
      if (code == "LOGIN"){
        string status;
        getline(iss, status);
        if(status == "200"){
            pthread_mutex_lock(&valid_login_mutex);
            valid_login = true;
            pthread_mutex_unlock(&valid_login_mutex);

            int client_listening_sockfd;
            if (setup_server_for_listening(client_listening_sockfd) < 0){
              cerr << "error setting up server" << endl;
              exit(EXIT_FAILURE);
            }
            char ip[my_ip.size()];
            strcpy(ip, my_ip.c_str());
            if(send(server_socket, ip, sizeof ip, 0) == -1)
              cerr << "error: send ip to server" << endl;
            cout << "sucessful login!" << endl;

            pthread_t new_connection_thread;
            if(pthread_create(&new_connection_thread, &detatch_thread_attr, accept_connections, (void*)&client_listening_sockfd) != 0){
              cerr << "error creating accept connections thread" << endl;
              exit(EXIT_FAILURE);
            }
            pthread_mutex_lock(&active_threads_mutex);
            active_threads.push_back(new_connection_thread);
            pthread_mutex_unlock(&active_threads_mutex);

        }
        else if (status == "500"){
          cout << "Username and password combinaiton not recognized" << endl;
        }

      }
      else if (code == "REGISTER"){
        string status;
        getline(iss, status);
        if (status == "200"){
          cout << "Successfully register! Please Login..." << endl;
        }
        else if (status == "500"){
          cerr << "Username taken, please try again..." << endl;
        }
      }
      else if (code == "LOCATION"){
        string friend_data;
        getline(iss, friend_data);
        friend_t temp_frd;
        istringstream _iss(friend_data);
        temp_frd.socket_fd = 0;
        getline(_iss, temp_frd.hostname, '|');
        getline(_iss, temp_frd.username);
        pthread_mutex_lock(&onlineFriends_mutex);
        onlineFriends.push_back(temp_frd);
        pthread_mutex_unlock(&onlineFriends_mutex);
        cout << temp_frd.username << " is online" << endl;
      }
      else if (code == "INVITE"){
        string from_user;
        string message;
        iss >> from_user;
        getline(iss, message);
        cout << "Recieved an invite from " << from_user << ":" << message << endl;


        pthread_mutex_lock(&invites_recieved_mutex);
        invites_recieved.push_back(from_user);
        pthread_mutex_unlock(&invites_recieved_mutex);

      }
      else if(code == "ACCEPT"){
        friend_t new_friend;
        new_friend.socket_fd = 0;
        string message;
        iss >> new_friend.username >> new_friend.hostname;
        getline(iss, message);
        cout << new_friend.username << " has accepted your invitation: " << message << endl;


        // pthread_mutex_lock(&invites_sent_mutex);
        // auto itr = std::find(invites_sent.begin(), invites_sent.end(), new_friend.username);
        // if (itr != invites_sent.end()){
        //   cout << "Invite accepted by: " << new_friend.username << " with message: " << message << endl;
        //   invites_sent.erase(itr);
        // }
        // pthread_mutex_unlock(&invites_sent_mutex);

        pthread_mutex_lock(&onlineFriends_mutex);
        onlineFriends.push_back(new_friend);
        pthread_mutex_unlock(&onlineFriends_mutex);
        cout << new_friend.username << " is online" << endl;

      }
      else if(code == "LOGOUT"){
        string from_user;
        iss >> from_user;
        pthread_mutex_lock(&onlineFriends_mutex);
        auto itr = std::find_if(onlineFriends.begin(), onlineFriends.end(), FindByUSR(from_user));
        if (itr != onlineFriends.end())
          onlineFriends.erase(itr);
        pthread_mutex_unlock(&onlineFriends_mutex);
        cout << from_user << " is offline" << endl;

      }
      }
    }
  return NULL;
}
bool valid_login_condition(){
  pthread_mutex_lock(&valid_login_mutex);
  bool result = valid_login;
  pthread_mutex_unlock(&valid_login_mutex);
  return result;
}
void *user_input(void *args){

  while(true){
    string command;
    getline(cin, command);
    istringstream iss(command);
    string type;
    iss >> type;
    if (!valid_login_condition()){
      if (type == "r" || type == "l"){
        string username;
        string password;
        cout << "username: ";
        cin >> username;
        my_username = username;
        cout << "password: ";
        cin >> password;
        username += ":" + password;
        username = command + " " + username;

        char* usr_pwd = new char[username.size() + 1];
        strcpy(usr_pwd, username.c_str());
        if((send(server_socket, usr_pwd, username.size(), 0) == -1))
          cerr << "error: send login to server" << endl;
      }
      else if (type == "exit"){
        exit(EXIT_SUCCESS);
      }
    }
    else{
      /*message*/
      if (type == "m"){
        string friend_username;
        string message;

        iss >> friend_username;
        getline(iss, message);
        int str_len = friend_username.size() + message.size() + 2;
        char mesg_buf[str_len];

        strcpy(mesg_buf, my_username.c_str());
        strcat(mesg_buf, "|");
        strcat(mesg_buf, message.c_str());
        //make sure friend?

        pthread_mutex_lock(&onlineFriends_mutex);

        auto itr = std::find_if(onlineFriends.begin(), onlineFriends.end(), FindByUSR(friend_username));
        if(itr != onlineFriends.end()){
          friend_t& frd = *itr;
          if(frd.socket_fd == 0){
            //need to establish connection with friend first
            frd.socket_fd = establishConnection(frd.hostname.c_str(), LISTENING_PORT);

            // need to create thread to handle messages FROM friend
            pthread_t friend_connection_thread;
            if(pthread_create(&friend_connection_thread, &detatch_thread_attr, friend_connections, (void*)&frd.socket_fd) != 0)
              continue;
            pthread_mutex_lock(&active_threads_mutex);
            active_threads.push_back(friend_connection_thread);
            pthread_mutex_unlock(&active_threads_mutex);

          }
          if((send(frd.socket_fd, mesg_buf, sizeof mesg_buf, 0) == -1))
            cerr << "error: send message to friend" << endl;
        }
        else{
          cout << friend_username << " is not online or does not exist or is not your friend" << endl;

        }
        pthread_mutex_unlock(&onlineFriends_mutex);

      }
      else if(type == "i" || type == "ia"){
        string usr;
        iss >> usr;
        auto itr = std::find_if(onlineFriends.begin(), onlineFriends.end(), FindByUSR(usr));
        if (itr == onlineFriends.end()){
          char mesg_to_server[command.size() + 1];
          strcpy(mesg_to_server, command.c_str());
          if((send(server_socket, mesg_to_server, sizeof mesg_to_server, 0)) == -1)
            cerr << "error sending invite to server" << endl;
        }
        else{
          cout << usr << " is already your friend" << endl;
        }

      }
      else if(type == "logout"){
        pthread_mutex_lock(&valid_login_mutex);
        valid_login = false;
        pthread_mutex_unlock(&valid_login_mutex);

        pthread_mutex_lock(&opened_sockets_mutex);
        for(int i = 0; i < opened_sockets.size(); i++)
          close(opened_sockets[i]);
        opened_sockets.clear();
        pthread_mutex_unlock(&opened_sockets_mutex);

        // pthread_mutex_lock(&active_threads_mutex);
        // for(int i = 0; i < active_threads.size(); i++){
        //   pthread_cancel(active_threads[i]);
        // }
        // active_threads.clear();
        // pthread_mutex_unlock(&active_threads_mutex);


        pthread_mutex_lock(&onlineFriends_mutex);
        onlineFriends.clear();
        pthread_mutex_unlock(&onlineFriends_mutex);
        char logout[7] = "logout";
        if(send(server_socket, logout, 7, 0) == -1)
          cerr << "error sending logout message" << endl;

      }
    }
  }
  return NULL;
}

int init_server(struct addrinfo *aip){
  int fd, err;
  int reuse = 1;
  if((fd = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol)) < 0){
    cerr << "error creating socket" << endl;
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &reuse, sizeof(int)) < 0){
    cerr << "error setting options for socket" << endl;
    goto errout;
  }
  #ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEPORT) failed");
  #endif
  if (::bind(fd, aip->ai_addr, aip->ai_addrlen) < 0){
    cerr << "error binding socket" << endl;
    goto errout;
  }
  if(listen(fd, 10) < 0){
    cerr << "error listening" << endl;
    goto errout;
  }
  return fd;
  errout:
    err = errno;
    close(fd);
    errno = err;
    cerr << "errno: " << errno << endl;
    return -1;
}
int setup_server_for_listening(int& listening_socket_fd){
  struct addrinfo hint;
  struct addrinfo *ailist, *aip;
  struct sockaddr_in  *sinp;
  int err = 0;
  socklen_t len = sizeof(sinp);
  char abuf[INET_ADDRSTRLEN];
  // to get FQDN as per project description
  char hostname[1024];
  hostname[1023] = '\0';
  if (gethostname(hostname, 1023) < 0){
    cerr << "error: gethostname" << endl;
    err = -1;
  }
  memset(&hint, 0, sizeof(struct addrinfo));
  hint.ai_flags = AI_CANONNAME;
  hint.ai_family = AF_UNSPEC;     /* ipv4 or ipv6 */
  hint.ai_socktype = SOCK_STREAM; /* tcp */
  hint.ai_protocol = 0;           /* Any protocol */
  hint.ai_canonname = NULL;
  hint.ai_addr = NULL;
  hint.ai_next = NULL;
  if ((err = getaddrinfo(hostname, LISTENING_PORT, &hint, &ailist)) != 0)
    cerr << "getaddrinfo error: "<< gai_strerror(err) << endl;
  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully init.
     If fails, we (close the socket and) try the next address. */
  for (aip = ailist; aip != NULL; aip = aip->ai_next) {
    if((listening_socket_fd = init_server(aip)) < 0){
      close(listening_socket_fd);
      continue;
    }
    sinp = (struct sockaddr_in *)aip->ai_addr;
    if(getsockname(listening_socket_fd, (struct sockaddr *) aip->ai_addr, &len) < 0){
      cerr << "error on getsockname" << endl;
      err = -1;
    }
    //cout << "listening on " << aip->ai_canonname << " port #" << ntohs(sinp->sin_port) << endl;
    err = 1;
    my_ip = inet_ntop(AF_INET, &sinp->sin_addr, abuf, INET_ADDRSTRLEN); // get readable ip address
    break;
  }
  freeaddrinfo(ailist);           /* No longer needed */
  return err;


}

void *_get_in_addr(struct sockaddr *sa){
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
void _read_in_config(serv_t& serv, const string configuration_file){
  ifstream config_file_s(configuration_file);
  string line;
  string buf;

  getline(config_file_s, line);
  istringstream iss(line);
  // servhost: servport
  getline(iss, serv.servhost, ':');
  getline(iss, buf, ' ');
  getline(iss, buf);
  serv.servport = stoi(buf);
  config_file_s.close();
}
void _check_input_files(const int argc, char const* const *argv, int *status){
  if (argc != 2){
    cout << "usage: messenger_server configration_file" << endl;
    *status = -1;
  }
  else if (access(argv[1], R_OK) != 0){
      cout << "unable to access " << argv[1] << endl;
      *status = -2;
  }
}
