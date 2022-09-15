# Network Draft


This document describes proposal of a MANET construction based on ec-crypt. For message overview and encryption details see «Documentation». 

By now, only encryption/decryption client is implemented in Python, called ec-crypt. It is supposed to be a "frontend" for networking software. 


## Networking principle

Originally, ec-crypt was conceived as a "frontend" for ad-hoc network for portable devices, where messages are exchanged with existing RF technologies: Wi-Fi Direct, Bluetooth, Zigbee, NFC, etc. 

Each device can act as a carrier, delivering messages across the network in epidemic manner. 

###Overview: 

1. Device A encounters device B. RF technologies allow automatic device detection. Specific device naming scheme should be designed to sieve generic devices. 
2. Once devices paired, they are exchanging MsgTable. MsgTable is a table that contains records of all encrypted messages stored on device. After MsgTable table exchange, devices exchange RequestTable - a filtered result of MsgTable. Filtering can be based on many criteria. 
3. Upon receiving RequestTable, each device forms all requested messages in one file. After receiving message file, each device parses it and records received messages in database. 

As both devices encounter other users, they will spread messages further, until they reach end point. As no delivery aknowledgement exist, it is important to implement garbage collector, which will delete old messages. 

As any end-point can receive messages by many routes, network extension should store hashes of all personal messages received. This list will allow to filter and ignore duplicates in the network. 

MsgTable table format draft: 

(Reciever's key ID);(Sender's key ID);(SHA-1 hash);(Message size in bytes);(Date received in unix time)

Real table example with three entries:

    2959_3642_19C2_76FE;E1DE_AC63_FCE8_6154;dafc2372a1288b6ea2b73a34f64888df93e9721e;1303;1430479675
    DB59_81AF_FD85_D343;2A03_3786_EF57_33C4;9fd400f6dde1ef0f38d8d0eaafda662a57efc018;255409;1430522603
    EA84_6D89_D08D_59A5;7D12_10B1_D59F_2A40;1c83aeda72a141604201ab5781f4ec74ed1f5744;66834;1430587037



## Implementation Notes

MANET networking extension should be designed to suite the needs of RF module. Most of OSes have different language support, so each OS will require different language and design approach. Also, it might be reasonable to equip networking software with message detection/notification triggered by specific key IDs, but leave encryption/decryption process to a separate software. 

Probably, it is worth investigate existing wireless file sharing solutions - like PirateBox (and PirateBox liveCD) and Byzanthium Linux to save time and effort.


## Extra Features 

Networking tools for MANET can be extended further by creating additional message exchange infrastructures: 

1. Message protocol can be extended to include base32-address of the sender or receiver, thus using I2P network as a gateway between I2P-enabled users.
2. Tor .onion addresses can be included the same way as I2P. Probably both network can be used, one as main, the other as fallback. 
3. Both networks were ported on mobile devices (Android) with server capabilities, so mobile devices can be used as gateways too.
4. I2P now supports ECDSA keys, which means I2P address can be made from MANET private key, as both work on P-256 curve. 
5. It is possible to organize a specialized central network hubs for storing messages, where users can post new messages and retrieve them by requests. Simple file sharing protocols (FTP or even HTTP-post) can be deployed, both in I2P and Tor. 
6. Messages can be exchange through so-called "dead drop" in public places. 
7. Any sneakernet can be used as transport. 
