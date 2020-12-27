""" outlines the dictionary used for packet types """
PACKETS = {
    None: 0,

    "EXIT": 1,
    "FULL": 2,
    "ACCEPT": 3,
    "USERNAME-ACCEPT": 4,
    "USERNAME_ACCEPT": 4,
    "USERNAME-TAKEN": 5,
    "USERNAME-INVALID": 6,
    "USERNAME_REJECT": 6,
    "ERROR": 7,

    "CLIENT_HELLO": 8,
    "SERVER_HELLO": 9,
    "CLIENT_AUTHENTICATE": 10,
    "SERVER_ENVELOPE": 11,
    "SEND_SERVER_BROADCAST": 12,
    "DISTRIBUTE_SERVER_BROADCAST": 13,
    "NO_SERVER_CONNECTION": 14,

    "SENDER_HELLO": 15,
    "RECIPIENT_HELLO": 16,
    "PEER_ENVELOPE": 17,
    "CLOSE_PEER_CONNECTION": 18,
    "NO_PEER_CONNECTION": 19
}

#Useful for debug outputs
INV_PACKETS = {v: k for k, v in PACKETS.items()}
