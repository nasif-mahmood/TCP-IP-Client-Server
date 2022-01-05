# TCP-IP-Client-Server
## About
This academic project allows information communication between multiple computers through **TCP/IP**
 * One computer acts as a server and accepts connections from different clients
 * After establishing a connection, the clients can send messages to the server
 * The server will count the number of words and characters in the message and send the information back
 * Multiple clients can connect to the server at the same time
## Tutorial
### Server
1. Download **server.c** and place in a directory of your choosing
2. Open a terminal in the directory and use **gcc -pthread -o server server.c** to compile the program
3. Use "**./server (port number)**" to run the program
4. Now the server should be awaiting connections from clients
### Client
1. Download **client.c** and place in a directory of your choosing
2. Open a terminal in the directory and use **gcc -o client client.c** to compile the program
3. Use "**./client (server IP address) (port number)**" to run the program
4. Now the client should be connected to the server
5. Enter messages into the client side console to receive the number of words and characters in them
6. Type in **exit** when you are finished to close the client
