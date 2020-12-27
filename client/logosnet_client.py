import argparse
import socket
import select
import queue
import sys
import LNP
from protocol import PACKETS, INV_PACKETS
import crypt

from lib.handshakes.server import ClientStateMachine
from lib.connector import LnpConnector
from lib.ui import extract_recipient

def get_args():
    '''
    Gets command line argumnets.
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    return parser.parse_args()

#Main method
def main():
    '''
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))

    inputs = [server, sys.stdin]
    outputs = [server]

    client_handshake_state_machine = ClientStateMachine()

    def show_broadcast(sender_username,message):
        if client_handshake_state_machine.is_username_accepted():
            #overwrite prompt with message
            sys.stdout.write('\r' + message.rstrip() + '\n')
            show_prompt()
        else:
            sys.stdout.write(message.rstrip()+'\n')

    client_handshake_state_machine.on_broadcast_received.add_handler(
        show_broadcast)

    def show_private_packet(sender_username,packet):
        if client_handshake_state_machine.is_username_accepted():
            #overwrite prompt with message
            sys.stdout.write('\r' + str(packet.rstrip()) + '\n')
            show_prompt()
        else:
            sys.stdout.write(str(message).rstrip()+'\n')

    client_handshake_state_machine.on_private_packet_received.add_handler(
        show_private_packet)

    def show_prompt():
        sys.stdout.write("> " + username + ": ")
        sys.stdout.flush()
        pass

    def on_accept():
        print("COMPLETE")
        show_prompt()

    client_handshake_state_machine.on_username_accept.add_handler(on_accept)

    lnp_connector = LnpConnector()

    def send_packet(*data):
        lnp_connector.send(server,*data)

    client_handshake_state_machine.on_packet_send.add_handler(send_packet)

    def send_packet_to_state_machine(socket,*data):
        print("received ",INV_PACKETS[data[0]])
        client_handshake_state_machine.handle_packet(*data)

    lnp_connector.after_receive.add_handler(send_packet_to_state_machine)

    def on_exceptional_socket(socket):
            print("Disconnected: Server exception")
            inputs.remove(socket)

    lnp_connector.on_exceptional_socket.add_handler(on_exceptional_socket)

    client_handshake_state_machine.start_connection()

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                lnp_connector.handle_readable_socket(s)

            ###
            ### Process user input
            ###
            else:

                msg = sys.stdin.readline()

                if msg == "exit()":
                    client_handshake_state_machine.graceful_close()

                elif not client_handshake_state_machine.is_username_accepted():
                    username = msg.rstrip()
                    #load signature
                    #prevent user from accidentally directory-traversing
                    #themself
                    signature_file = f"{username}.cert".replace('/','')
                    signature = crypt.load_signature(signature_file)
                    try:
                        client_handshake_state_machine.set_username(
                            username,
                            signature)
                    except:
                        #handshake is waiting for confirmation on a previous username
                        #probably best to do nothing
                        pass
                #ordinary message
                else:
                    recipient = extract_recipient(msg)
                    if recipient:
                        client_handshake_state_machine.send_private_packet(
                            recipient, msg.encode('utf-8'))
                    else:
                        client_handshake_state_machine.send_broadcast(
                            msg)

                if client_handshake_state_machine.is_username_accepted():
                    show_prompt()

        for s in exceptional:
            lnp_connector.handle_exceptional_socket(s)

    server.close()

if __name__ == '__main__':
    main()
