#include <iostream>
#include <unistd.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cerrno> /*errno*/
#include <cstring> /*memset*/
#include <netdb.h>
#include <signal.h>
#include <algorithm>
using namespace std;

typedef struct user_t{
  string username;
  string password;
  string hostname;
  int socket_fd;
  bool isOnline  = false;
  vector<user_t> friends;

} user_t;

typedef struct config_t{
  string keyword;
  unsigned int value;
} config_t;

struct FindByUSRPWD{
  const string usr;
  const string pwd;
  FindByUSRPWD(const string& usr, const string& pwd) : usr(usr), pwd(pwd) {}
  bool operator() (const user_t& u) const{
    return u.username == usr && u.password == pwd;
  }
};
struct FindByUSR{
  const string usr;
  FindByUSR(const string& usr): usr(usr) {}
  bool operator() (const user_t u) const{
    return u.username == usr;
  }
};

struct FindBySOCKandONLINE{
  const int sock;
  FindBySOCKandONLINE(const int& sock): sock(sock) {}
  bool operator() (const user_t u) const{
    return u.socket_fd == sock && u.isOnline;
  }
};

fd_set master; /* master file descriptor list */
int fdmax; /* max file descriptor number */
vector<user_t> all_users; /* holds all user info, made global for sig hanler purposes */
string user_info_file;
int total_users_online = 0;


void sigint_handler(int s);
void _check_input_files(const int argc, char const* const *argv, int *status);
void _read_in_users();
void _read_in_config(vector<config_t>& configs, const string configuration_file);
int init_server(struct addrinfo *aip);
int setup_server_for_listening(int& listening_socket_fd, const vector<config_t>& configs);
void *_get_in_addr(struct sockaddr *sa);
void _interpret_response(char * msg, int nbytes, const int sockfd);
void _handle_login(char *msg, const int sockfd);
void _handle_register(char* msg, const int sockfd);
void _handle_invite(char* msg, const int sockfd);
void _handle_invite_acc(char* msg, const int sockfd);
void _handle_logout(const int sockfd);

int main(int argc, char *argv[]){
  vector<config_t> configs;
  int listening_socket_fd;
  int status = 0;
  memset(&master, 0, sizeof master);


  _check_input_files(argc, argv, &status);
  if(status != 0)
    exit(EXIT_FAILURE);

  /* safe to use args as pathnames*/
  user_info_file = argv[1];
  string configuration_file = argv[2];
  _read_in_users();
  _read_in_config(configs, configuration_file);

  /* init signal handler */
  struct sigaction sa;
  sa.sa_handler = sigint_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if(sigaction(SIGINT, &sa, NULL) == -1){
    cerr << "sigaction" << endl;
    exit(EXIT_FAILURE);
  }
  FD_ZERO(&master);
  if (setup_server_for_listening(listening_socket_fd, configs) < 0){
    cerr << "error setting up server" << endl;
    exit(EXIT_FAILURE);
  }
  FD_SET(listening_socket_fd, &master); /* add listening socket to the master set */
  fdmax = listening_socket_fd; /* keep track of the biggest file descriptor, which is currently listening_socket_fd */

  socklen_t addrlen;
  fd_set readfds;
  struct sockaddr_storage clientaddr;
  int newfd;
  int nbytes;
  char clientIP[INET_ADDRSTRLEN];
  char buf[256];
  while(1){
    // start accepting connections
    // we will need to either use pthreads to handle the multiple connections or select()
    // select: way of checking whether data is available on any of a group of file desciptors
    readfds = master;
    if(select(fdmax + 1, &readfds, NULL, NULL, NULL) == -1){
      cerr << "select" << endl;
      exit(EXIT_FAILURE);
    }
    /* run through existig connection looking for data to read */
    for (int i = 0; i <= fdmax; i++){
      if (FD_ISSET(i, &readfds)){ /* i is fd we can read! */
        if (i == listening_socket_fd){
          /* new connection */
          addrlen = sizeof clientaddr;
          if((newfd = accept(listening_socket_fd, (struct sockaddr *)&clientaddr, &addrlen)) < 0)
            cerr << "accept" << endl;
          else{
            FD_SET(newfd, &master); /* add newfd to master */
            if(newfd > fdmax)
              fdmax = newfd; /* update highest fd if neccessary */
            //cout << "new connection from " << inet_ntop(clientaddr.ss_family, _get_in_addr((struct sockaddr *) &clientaddr), clientIP, INET_ADDRSTRLEN) << endl;
          }
        }
        else{
          // already established fd, so read data from this client
          if((nbytes = recv(i, buf, sizeof buf, 0)) <= 0){
            // got error OR connection was closed by the client
            if(nbytes == 0){/* connection closed by client */
              //cout << "connection closed on port #" << i << endl;
              auto itr = std::find_if(all_users.begin(), all_users.end(), FindBySOCKandONLINE(i));
              if(itr != all_users.end()){
                _handle_logout(i);
                user_t &user = *itr;
                user.socket_fd = 0;
                close(i);
                FD_CLR(i, &master);
              }
              /*
                delete users location information
                inform friends of user that user is offline
                decrement total_users_online
              */
            }
            else{
              cerr << "recv" << endl;
            }
          }
          else{ /* data received */
            // interpret data, and if neccessary send data to friend
            buf[nbytes] = '\0';
            _interpret_response(buf, nbytes, i);
            memset(buf, 0, sizeof buf);

          }
        }
      }
    }
  }
}
void _handle_login(char *msg, const int sockfd){
  string message = msg;
  message = message.substr(2, message.size());
  string username;
  string password;
  string buf;
  char resp_buf[1024];
  int numbytes = 0;
  istringstream iss(message);
  char send_msg[256];
  getline(iss, username, ':');
  getline(iss, password);
  auto it = std::find_if(all_users.begin(), all_users.end(), FindByUSRPWD(username, password));
  if(it != all_users.end()){
    user_t &user = *it;
    strcpy(send_msg, "LOGIN 200\0");
    // send sucessful login status to client user
    if((send(sockfd, send_msg, 11, 0) == -1))
      cerr << "send" << endl;
    // wait to recv user's location info
    if((numbytes = recv(sockfd, resp_buf, sizeof resp_buf, 0)) < 0)
      cerr << "recv" << endl;
    resp_buf[numbytes] = '\0';
    user.hostname = resp_buf;

    user.isOnline = true;
    user.socket_fd = sockfd;
    // send location info of user's friends to user
    // then send location info of user to all online friends
    // need to search through allusers, if name matches that of a friend,
    // check if that person is online, then try and send info
    for (int i = 0; i < user.friends.size(); i++){
      auto frd_it = std::find_if(all_users.begin(), all_users.end(), FindByUSR(user.friends[i].username));
      if (frd_it != all_users.end()){
        user_t& frd = *frd_it;
        if(frd.isOnline){
          char location_str[10] = "LOCATION ";
          int message_size = 10 + frd.hostname.size() + frd.username.size() + 2;
          char *friendhost = new char[message_size];
          strcpy(friendhost, location_str);
          strcat(friendhost, frd.hostname.c_str());
          strcat(friendhost, "|");
          strcat(friendhost, frd.username.c_str());
          if(send(sockfd, friendhost, message_size, 0) == -1)
            cerr << "error sending friend host name to user" << endl;

          int userhost_len = 10 + user.hostname.size() + user.username.size() + 2;
          char *userhost = new char[userhost_len];
          strcpy(userhost, location_str);

          strcat(userhost, user.hostname.c_str());
          strcat(userhost, "|");
          strcat(userhost, user.username.c_str());

          if(send(frd.socket_fd, userhost, userhost_len, 0) == -1)
            cerr << "error sending user host to friend" << endl;
          delete [] friendhost;
          delete [] userhost;
        }
      }
    }
    cout << "total users online: " << ++total_users_online << endl;
  }else{
    strcpy(send_msg, "LOGIN 500\0");
    if((send(sockfd, send_msg, 11, 0) == -1))
      cerr << "send" << endl;
  }
}

void _handle_register(char* msg, const int sockfd){
  string message = msg;
  message = message.substr(2, message.size());
  string username;
  string password;
  string buf;
  char resp_buf[1024];
  int numbytes = 0;
  istringstream iss(message);
  char send_msg[256];
  getline(iss, username, ':');
  getline(iss, password);
  auto it = std::find_if(all_users.begin(), all_users.end(), FindByUSR(username));
  if(it == all_users.end()){//user does not exist yet
    user_t new_usr;
    new_usr.username = username;
    new_usr.password = password;
    strcpy(send_msg, "REGISTER 200\0");
    // send sucessful login status to client user
    if((send(sockfd, send_msg, 13, 0) == -1))
      cerr << "send" << endl;
    all_users.push_back(new_usr);

  }else{
    strcpy(send_msg, "REGISTER 500\0");
    if((send(sockfd, send_msg, 13, 0) == -1))
      cerr << "send" << endl;
  }
}

void _handle_invite(char* msg, const int sockfd){
  // i potential_friend_username [whatever_message]
  string str_msg = msg;
  str_msg = str_msg.substr(2, str_msg.size());

  string pot_frd_name;
  string message;
  istringstream iss(str_msg);
  iss >> pot_frd_name;
  getline(iss, message);

  auto itr = std::find_if(all_users.begin(), all_users.end(), FindByUSR(pot_frd_name));
  auto u_itr = std::find_if(all_users.begin(), all_users.end(), FindBySOCKandONLINE(sockfd));
  if(itr != all_users.end() && u_itr != all_users.end()){
    //ask pos_frd if want to be friend with user
    user_t &pot_frd = *itr;
    user_t &cur_usr = *u_itr;
    char INVITE[8] = "INVITE ";
    int bufsize = 7 + cur_usr.username.size() + message.size() + 2;
    char send_msg[bufsize];

    strcpy(send_msg, INVITE);
    strcat(send_msg, cur_usr.username.c_str());
    strcat(send_msg, " ");
    strcat(send_msg, message.c_str());
    if(send(pot_frd.socket_fd, send_msg, bufsize, 0) == -1)
      cerr << "error: sending invite" << endl;
  }
}

void _handle_invite_acc(char* msg, const int sockfd){
  /*accept invitation: after seeing an invitation message, the user can use the
    command "ia" to accept the invitation: ia inviter_username [whatever_message].
    The invitation acceptance message is sent to the server, which in turn
    forwards the message to the initial inviter. The server will also update the
    friend list of both users.
  */
  string str_msg = msg;
  str_msg = str_msg.substr(3, str_msg.size());
  string inviter_name;
  string message;
  istringstream iss(str_msg);
  iss >> inviter_name;
  getline(iss, message);

  auto itr = std::find_if(all_users.begin(), all_users.end(), FindByUSR(inviter_name));
  auto f_itr = std::find_if(all_users.begin(), all_users.end(), FindBySOCKandONLINE(sockfd));

  if(itr != all_users.end() && f_itr != all_users.end()){
    user_t &inviter_user = *itr;
    user_t &invited_user = *f_itr;

    inviter_user.friends.push_back(invited_user);
    invited_user.friends.push_back(inviter_user);

    char ACCEPT[8] = "ACCEPT ";
    int bufsize = 7 + invited_user.username.size() + invited_user.hostname.size() + message.size() + 3;
    char send_msg[bufsize];
    strcpy(send_msg, ACCEPT);
    strcat(send_msg, invited_user.username.c_str());
    strcat(send_msg, " ");
    strcat(send_msg, invited_user.hostname.c_str());
    strcat(send_msg, " ");
    strcat(send_msg, message.c_str());

    if(send(inviter_user.socket_fd, send_msg, bufsize, 0) == -1)
      cerr << "error: sending invite accceptance to inviter" << endl;

    char LOCATION[10] = "LOCATION ";
    bufsize = 9 + inviter_user.username.size() + inviter_user.hostname.size() + message.size() + 2;
    char send_msg_to_invited[bufsize];
    strcpy(send_msg_to_invited, LOCATION);
    strcat(send_msg_to_invited, inviter_user.hostname.c_str());
    strcat(send_msg_to_invited, "|");
    strcat(send_msg_to_invited, inviter_user.username.c_str());

    if(send(invited_user.socket_fd, send_msg_to_invited, bufsize, 0) == -1)
      cerr << "error: sending invite accceptance to invited" << endl;

  }
}

void _handle_logout(const int sockfd){

  auto itr = std::find_if(all_users.begin(), all_users.end(), FindBySOCKandONLINE(sockfd));
  if(itr != all_users.end()){
    user_t &user = *itr;
    user.isOnline = false;
    user.hostname = "";

    cout << "total users online: " << --total_users_online << endl;
    for(int i = 0; i < user.friends.size(); i++){
      auto frd_it = std::find_if(all_users.begin(), all_users.end(), FindByUSR(user.friends[i].username));
      if (frd_it != all_users.end()){
        user_t& frd = *frd_it;
        if(frd.isOnline){
          char LOGOUT[8] = "LOGOUT ";
          int bufSize = 7 + user.username.size() + 1;
          char *userhost = new char[bufSize];
          strcpy(userhost, LOGOUT);
          strcat(userhost, user.username.c_str());
          if(send(frd.socket_fd, userhost, bufSize, 0) == -1)
            cerr << "error sending user host to friend" << endl;
          delete [] userhost;
        }
      }
    }
  }
}

void _interpret_response(char * msg, int nbytes, const int sockfd){
  string str_msg = msg;
  istringstream iss(str_msg);
  string type;
  iss >> type;

  char send_msg[256];

  if(type == "l") _handle_login(msg, sockfd);
  else if(type == "r") _handle_register(msg, sockfd);
  else if(type == "i") _handle_invite(msg, sockfd);
  else if(type == "ia") _handle_invite_acc(msg, sockfd);
  else if(strcmp(msg, "logout") == 0) _handle_logout(sockfd);
  else{
    cerr << "invalid response from client" << endl;
    strcpy(send_msg, "400\0");
    if((send(sockfd, send_msg, 4, 0) == -1))
      cerr << "send" << endl;
  }
}

void *_get_in_addr(struct sockaddr *sa){
  if(sa->sa_family == AF_INET){
      return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sigint_handler(int s){
  int saved_errno = errno;

  /* close all opened sockets */
  for(int i = 0; i <= fdmax; i++){
    /* close & remove connection from master list */
    if(FD_ISSET(i, &master)){
      close(i);
      FD_CLR(i, &master);
    }
  }

  // write all user accounts into user_info_file
  ofstream out_s(user_info_file);
  if(out_s.is_open()){
    for(int i = 0; i < all_users.size(); i++){
      // user1|password1|user2;user5;user6
      out_s << all_users[i].username << "|" << all_users[i].password << "|";
      if(!all_users[i].friends.empty()){
        for (int j = 0; j < all_users[i].friends.size() - 1; j++)
          out_s << all_users[i].friends[j].username << ";";
        out_s << all_users[i].friends[all_users[i].friends.size() - 1].username;
      }
      out_s << endl;
    }
  }
  else{
    cerr << "error opening " << user_info_file << endl;
    exit(EXIT_FAILURE);
  }
  out_s.close();
  all_users.clear();
  exit(EXIT_SUCCESS);
}
int setup_server_for_listening(int& listening_socket_fd, const vector<config_t>& configs){
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
  if ((err = getaddrinfo(hostname, to_string(configs[0].value).c_str(), &hint, &ailist)) != 0)
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
    cout << "listening on " << aip->ai_canonname << " port #" << ntohs(sinp->sin_port) << endl;
    err = 1;
    //cout << inet_ntop(AF_INET, &sinp->sin_addr, abuf, INET_ADDRSTRLEN) << endl; // get readable ip address
    break;
  }
  freeaddrinfo(ailist);           /* No longer needed */
  return err;


}

int init_server(struct addrinfo *aip){
  int fd, err;
  int reuse = 1;
  if((fd = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol)) < 0){
    cerr << "error creating socket" << endl;
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0){
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
void _read_in_config(vector<config_t>& configs, const string configuration_file){
  ifstream config_file_s(configuration_file);
  string line;
  string buf;
  while(getline(config_file_s, line)){
    config_t temp_confg;
    istringstream iss(line);
    // keyword: value
    getline(iss, temp_confg.keyword, ':');
    getline(iss, buf, ' ');
    getline(iss, buf);
    temp_confg.value = stoi(buf);
    configs.push_back(temp_confg);
  }
  config_file_s.close();
}
void _read_in_users(){
  ifstream user_file_s(user_info_file);
  string line;
  while(getline(user_file_s, line)){
    user_t temp_usr;
    user_t temp_frd;
    string temp_frd_usrname;
    istringstream iss(line);
    // user1|password1|user2;user5;user6
    getline(iss, temp_usr.username, '|');
    getline(iss, temp_usr.password, '|');
    while(getline(iss, temp_frd_usrname, ';')){
      temp_frd.username = temp_frd_usrname;
      temp_usr.friends.push_back(temp_frd);
    }
    all_users.push_back(temp_usr);
  }

  user_file_s.close();
}
void _check_input_files(const int argc, char const* const *argv, int *status){
  if (argc != 3){
    cout << "usage: messenger_server  user_info_file configration_file" << endl;
    *status = -1;
  }
  else{
    if (access(argv[1], R_OK) != 0){
      cout << "unable to access " << argv[1] << endl;
      *status = -2;
    }
    if (access(argv[2], R_OK) != 0){
      cout << "unable to access " << argv[2] << endl;
      *status = -3;
    }
  }
}
