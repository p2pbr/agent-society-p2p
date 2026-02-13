# cli/interface.py
"""
cli/interface.py
Implements the Command Line Interface (CLI) for user interaction with the P2P node.
Handles user input for commands like connecting to peers and sending messages.
"""
import asyncio
import logging
from protocol.message import Message

class CLI:
    """
    Command Line Interface for interacting with the P2P node.
    Allows sending messages and displays received messages.
    """
    def __init__(self, node):
        self.node = node
        self.input_queue = asyncio.Queue()
        self.reader_task = None
        logging.info("CLI initialized.")

    async def start(self):
        """
        Starts the CLI, listening for user input.
        """
        logging.info("CLI started. Type 'exit' to quit.")
        # This task reads from stdin without blocking the event loop
        self.reader_task = asyncio.create_task(self._read_stdin())
        while True:
            user_input = await self.input_queue.get()
            if user_input.lower() == 'exit':
                logging.info("Exiting CLI.")
                break
            elif user_input.lower().startswith('connect '):
                try:
                    parts = user_input.split(' ')
                    peer_host = parts[1]
                    peer_port = int(parts[2])
                    await self.node.connect_to_peer(peer_host, peer_port)
                except (IndexError, ValueError):
                    logging.warning("Usage: connect <host> <port>")
                except Exception as e:
                    logging.error(f"Error connecting: {e}")
            elif user_input.lower().startswith('send '):
                try:
                    parts = user_input.split(' ', 2)
                    peer_node_id = parts[1] # Now it expects a node_id
                    chat_text = parts[2]
                    
                    chat_message = Message(
                        message_type="chat",
                        node_id=self.node.get_id(),
                        payload={"text": chat_text}
                    )
                    await self.node.send_message(peer_node_id, chat_message)
                except (IndexError, ValueError):
                    logging.warning("Usage: send <peer_node_id> <message>")
                except Exception as e:
                    logging.error(f"Error sending message: {e}")
            else:
                logging.info(f"You typed: {user_input}")
                # For now, just echoing. Later, this will send messages to peers.

    async def _read_stdin(self):
        """
        Reads input from stdin and puts it into the input_queue.
        """
        while True:
            line = await asyncio.to_thread(input, "> ")
            await self.input_queue.put(line)

    def display_message(self, message):
        """
        Displays a message to the user without interfering with the current input line.
        """
        # This is a bit of a hack for CLI, in a proper UI framework it would be simpler.
        # It moves the cursor up, clears the line, prints the message,
        # then redraws the prompt and the current input.
        # This will work best in a terminal that supports ANSI escape codes.
        try:
            # Clear current input line (if any)
            print("\r\033[K", end="")
            print(f"[MSG] {message}")
            print(f"> ", end="", flush=True)
        except Exception as e:
            logging.error(f"Error displaying message in CLI: {e}")
            print(f"\n[MSG] {message}\n> ", end="", flush=True) # Fallback
