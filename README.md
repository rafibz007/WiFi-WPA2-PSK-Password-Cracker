# WiFi-WPA2-PSK-Password-Cracker

The following repo contains my custom implementation of Wifi WPA2 PSK password cracking tool.

Python sockets accepting raw bytes were used for that purpose and whole packet parsing was done from scratch.

The project supports couple of features which are defined in separate python files in the root of the project.

Unfortunately the project was not finished. In current state it is able to 
 - list nearby networks on multiple channels simultaneously
 - deauthenticate connected devices to particular Access Point
 - capture 4-way handhake for particular Access Point
Password cracking using 4-way handshake data has not been implemented yet.

Project documentation with more details is attached in the root of the repository in polish language.
