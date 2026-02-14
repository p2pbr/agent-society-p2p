# main.py

"""
main.py
Entry point for the P2P network application.
Initializes the P2P node and the command-line interface (CLI),
and runs them concurrently.
"""

import asyncio
import logging
import argparse

from core.node import Node
from cli.interface import CLI

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def main():
    """
    Main function to initialize and run the P2P node and CLI.
    """
    parser = argparse.ArgumentParser(description="P2P Network Node")
    parser.add_argument('--port', type=int, default=0,
                        help='Port for the P2P network to listen on (0 for random)')
    parser.add_argument('--web-port', type=int, default=8080,
                        help='Port for the local web server')
    parser.add_argument('--bootstrap', type=str, action='append',
                        help='Bootstrap node in the format host:port (can be specified multiple times)')
    
    args = parser.parse_args()

    bootstrap_nodes = []
    if args.bootstrap:
        for bs_node in args.bootstrap:
            try:
                host, port = bs_node.split(':')
                bootstrap_nodes.append((host, int(port)))
            except ValueError:
                logging.error(f"Invalid bootstrap node format: {bs_node}. Expected host:port")
                return

    node = Node(port=args.port, web_port=args.web_port, bootstrap_nodes=bootstrap_nodes)
    cli = CLI(node)
    node.cli = cli

    # Start the node and CLI concurrently
    node_task = asyncio.create_task(node.start())
    cli_task = asyncio.create_task(cli.start())

    # Explicitly print the P2P and Web ports for easier debugging/testing
    await asyncio.sleep(1) # Give the node a moment to bind and get its actual port
    p2p_host, p2p_port = node.get_address()
    print(f"NODE_P2P_PORT:{p2p_port}")
    print(f"NODE_WEB_PORT:{node.web_port}")

    await asyncio.gather(node_task, cli_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Node is shutting down.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
