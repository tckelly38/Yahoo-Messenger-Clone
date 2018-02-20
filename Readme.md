#Project 2

First `make`

Run the server: `./messenger_server user config`

Run clients: `./messenger_client client_config`

This application has been tested on OSX(10.13.1) running clang 9.0.0, and the linprog(Red Hat v4.8.5-11) machines running gcc 4.8.5.

This application mimics a peer to peer messaging server with a central server used to communicate specific location information and to handle invites between users.

The I/O multiplexing scheme in the `messenger_server` is implemented with the select() system call.

The I/O multiplexing scheme in the `messenger_client` is implemented with POSIX threads.

You must logout before exiting the client program.

you must login after successfully registering.

Issues that don't interfere with project specifications and shouldn't effect testing:

* a user can accept an invite from someone who didn't send an invite (forcing them to be a friend)
