# bootstrap/client.py
"""
bootstrap/client.py
Implements the BootstrapClient responsible for connecting to predefined
bootstrap nodes to initiate peer discovery for a new node joining the network.
"""
import asyncio
import logging

from protocol.message import Message

class BootstrapClient:
    """
    Handles connecting to predefined bootstrap nodes to initiate peer discovery.
    """
    def __init__(self, node, bootstrap_nodes: list):
        """
        :param node: The P2P node instance.
        :param bootstrap_nodes: A list of (host, port) tuples for bootstrap nodes.
        """
        self.node = node
        self.bootstrap_nodes = bootstrap_nodes
        logging.info(f"BootstrapClient initialized with {len(bootstrap_nodes)} bootstrap nodes.")

    async def start_discovery(self):
        """
        Attempts to connect to bootstrap nodes and exchange 'hello' messages.
        """
        if not self.bootstrap_nodes:
            logging.warning("No bootstrap nodes configured. Starting network without initial connections.")
            return

        logging.info("Attempting to connect to bootstrap nodes...")
        for host, port in self.bootstrap_nodes:
            # Check if we are trying to connect to ourselves
            if host == self.node.host and port == self.node.port:
                logging.info(f"Skipping self-connection attempt to bootstrap {host}:{port}")
                continue

            success = await self.node.connect_to_peer(host, port)
            if success:
                logging.info(f"Successfully connected to bootstrap node {host}:{port}")
            else:
                logging.warning(f"Failed to connect to bootstrap node {host}:{port}")
        
        # After attempting connections, proactively send a peer_list to connected peers
        # if len(self.node.peers) > 0:
        #     await self._send_initial_peer_list()

    async def _send_initial_peer_list(self):
        """
        Sends an initial peer_list message to all newly connected peers.
        This is a placeholder and might be better handled by a periodic task in the Node.
        """
        # This will be integrated into a more general peer management in Node.
        pass
