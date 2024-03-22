# CN_PROJECT

In this socket programming assignment, we will be implementing a secure peer-to-peer terminal emulation application using C programming language, using server as intermediate and with a secure communication using SSL encryption. Controller client will be accessing the remote client to run terminal commands. This project aims to provide a secure and efficient means of remote command execution.
To address the challenges presented by NAT and firewalls, the project will incorporate a relay server as intermediary. This server will play a vital role in facilitating authentication and communication between the controller client and the remote client, overcoming network obstacles and ensuring a reliable connection.
This approach aligns with the goal of providing a secure alternative to traditional remote screen sharing, particularly suited for scenarios with slower bandwidth or heightened security requirements.
Remote client will be started first which connects to the server and then controller client will connect to the server. The server will then establish data path between them.
