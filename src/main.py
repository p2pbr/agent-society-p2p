# main.py

"""
main.py
Entry point for the P2P network application.
Initializes the P2P node and the command-line interface (CLI),
and runs them concurrently.
"""

import asyncio
import logging

from core.node import Node
from cli.interface import CLI

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def main():
    """
    Main function to initialize and run the P2P node and CLI.
    """
    node = Node(bootstrap_nodes=[])
    cli = CLI(node)
    node.cli = cli

    # Start the node and CLI concurrently
    node_task = asyncio.create_task(node.start())
    cli_task = asyncio.create_task(cli.start())

    await asyncio.gather(node_task, cli_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Node is shutting down.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
