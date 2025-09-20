import asyncio
import aiohttp
import aiosqlite
import json
import base64
import hashlib
import struct
import socket
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import argparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Aetherium")

class Crypto:
    @staticmethod
    def generate_keypair():
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_data(private_key, data):
        return private_key.sign(data)

    @staticmethod
    def verify_signature(public_key, signature, data):
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def public_key_to_id(public_key):
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(public_bytes).digest()[:20]

class DHTNode:
    def __init__(self, node_id, ip, port):
        self.node_id = node_id
        self.ip = ip
        self.port = port

class DHT:
    def __init__(self, node_id, k=8):
        self.node_id = node_id
        self.k = k
        self.buckets = [[] for _ in range(160)]
        self.values = {}

    def distance(self, id1, id2):
        return int.from_bytes(id1, 'big') ^ int.from_bytes(id2, 'big')

    def add_node(self, node):
        distance = self.distance(self.node_id, node.node_id)
        bucket_index = distance.bit_length() - 1 if distance > 0 else 0
        bucket = self.buckets[bucket_index]
        
        for i, n in enumerate(bucket):
            if n.node_id == node.node_id:
                bucket[i] = node
                return
        
        if len(bucket) < self.k:
            bucket.append(node)
        else:
            pass

    def find_nodes(self, target_id):
        distances = []
        for bucket in self.buckets:
            for node in bucket:
                distance = self.distance(target_id, node.node_id)
                distances.append((distance, node))
        distances.sort(key=lambda x: x[0])
        return [node for _, node in distances[:self.k]]

class P2PProtocol:
    def __init__(self, node_id, host, port, crypto, dht):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.crypto = crypto
        self.dht = dht
        self.peers = {}
        self.server = None

    async def connect_to_peer(self, ip, port):
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            self.peers[(ip, port)] = (reader, writer)
            await self.send_handshake(writer)
            asyncio.create_task(self.handle_peer(reader, writer, ip, port))
            return True
        except Exception as e:
            logger.error(f"Connection failed to {ip}:{port}: {e}")
            return False

    async def send_handshake(self, writer):
        handshake = struct.pack('!B', 0x01) + self.node_id
        writer.write(handshake)
        await writer.drain()

    async def handle_peer(self, reader, writer, ip, port):
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                await self.process_message(data, writer)
        except Exception as e:
            logger.error(f"Error handling peer {ip}:{port}: {e}")
        finally:
            writer.close()
            self.peers.pop((ip, port), None)

    async def process_message(self, data, writer):
        message_type = data[0]
        if message_type == 0x01:
            await self.handle_handshake(data[1:], writer)
        elif message_type == 0x02:
            await self.handle_pex_request(writer)
        elif message_type == 0x03:
            await self.handle_dht_query(data[1:], writer)

    async def handle_handshake(self, peer_id, writer):
        peer_node = DHTNode(peer_id, writer.get_extra_info('peername')[0], writer.get_extra_info('peername')[1])
        self.dht.add_node(peer_node)
        response = struct.pack('!B', 0x01) + self.node_id
        writer.write(response)
        await writer.drain()

    async def handle_pex_request(self, writer):
        peers_list = []
        for node in self.dht.buckets:
            for n in node:
                peers_list.append((n.ip, n.port))
        response = struct.pack('!B', 0x02) + json.dumps(peers_list).encode()
        writer.write(response)
        await writer.drain()

    async def handle_dht_query(self, data, writer):
        target_id = data[:20]
        nodes = self.dht.find_nodes(target_id)
        nodes_data = []
        for node in nodes:
            nodes_data.append({
                'id': base64.b64encode(node.node_id).decode(),
                'ip': node.ip,
                'port': node.port
            })
        response = struct.pack('!B', 0x03) + json.dumps(nodes_data).encode()
        writer.write(response)
        await writer.drain()

    async def start_server(self):
        self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)
        async with self.server:
            await self.server.serve_forever()

    async def handle_connection(self, reader, writer):
        data = await reader.read(1024)
        if data and data[0] == 0x01:
            peer_id = data[1:21]
            peer_ip = writer.get_extra_info('peername')[0]
            peer_port = writer.get_extra_info('peername')[1]
            peer_node = DHTNode(peer_id, peer_ip, peer_port)
            self.dht.add_node(peer_node)
            response = struct.pack('!B', 0x01) + self.node_id
            writer.write(response)
            await writer.drain()
            asyncio.create_task(self.handle_peer(reader, writer, peer_ip, peer_port))

class BootstrapClient:
    def __init__(self, bootstrap_url, node_id, ip, port):
        self.bootstrap_url = bootstrap_url
        self.node_id = node_id
        self.ip = ip
        self.port = port

    async def register_and_fetch_peers(self):
        async with aiohttp.ClientSession() as session:
            data = {
                'node_id': base64.b64encode(self.node_id).decode(),
                'ip': self.ip,
                'port': self.port
            }
            try:
                async with session.post(self.bootstrap_url, json=data) as response:
                    result = await response.json()
                    return result.get('nodes', [])
            except Exception as e:
                logger.error(f"Bootstrap error: {e}")
                return []

class ContentManager:
    def __init__(self, crypto, dht, p2p):
        self.crypto = crypto
        self.dht = dht
        self.p2p = p2p
        self.content = {}

    async def publish_content(self, site_private_key, content_path):
        pass

    async def retrieve_content(self, site_address):
        pass

class ProxyServer:
    def __init__(self, host, port, content_manager):
        self.host = host
        self.port = port
        self.content_manager = content_manager

    async def handle_request(self, reader, writer):
        request = await reader.read(4096)
        try:
            request_lines = request.decode().split('\r\n')
            if not request_lines:
                return
            first_line = request_lines[0].split()
            if len(first_line) < 2:
                return
            method, path = first_line[0], first_line[1]
            
            if path.endswith('.aeth'):
                site_address = path.split('/')[2].split('.')[0]
                content = await self.content_manager.retrieve_content(site_address)
                if content:
                    response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(content)}\r\n\r\n{content}"
                else:
                    response = "HTTP/1.1 404 Not Found\r\n\r\n"
            else:
                response = "HTTP/1.1 404 Not Found\r\n\r\n"
            
            writer.write(response.encode())
            await writer.drain()
        except Exception as e:
            logger.error(f"Proxy error: {e}")
        finally:
            writer.close()

    async def start(self):
        server = await asyncio.start_server(self.handle_request, self.host, self.port)
        async with server:
            await server.serve_forever()

class AetheriumNode:
    def __init__(self, mode='client', host='0.0.0.0', port=7070, bootstrap_url='http://localhost/bootstrap.php'):
        self.mode = mode
        self.host = host
        self.port = port
        self.bootstrap_url = bootstrap_url
        self.crypto = Crypto()
        self.private_key, self.public_key = self.crypto.generate_keypair()
        self.node_id = self.crypto.public_key_to_id(self.public_key)
        self.dht = DHT(self.node_id)
        self.p2p = P2PProtocol(self.node_id, host, port, self.crypto, self.dht)
        self.bootstrap_client = BootstrapClient(bootstrap_url, self.node_id, host, port)
        self.content_manager = ContentManager(self.crypto, self.dht, self.p2p)
        self.proxy = ProxyServer('127.0.0.1', 8080, self.content_manager)

    async def start(self):
        logger.info(f"Starting Aetherium node in {self.mode} mode")
        logger.info(f"Node ID: {base64.b64encode(self.node_id).decode()}")
        
        asyncio.create_task(self.p2p.start_server())
        
        peers = await self.bootstrap_client.register_and_fetch_peers()
        for peer in peers:
            asyncio.create_task(self.p2p.connect_to_peer(peer['ip'], peer['port']))
        
        if self.mode == 'client':
            asyncio.create_task(self.proxy.start())
        
        await asyncio.Future()

def main():
    parser = argparse.ArgumentParser(description='Aetherium P2P Node')
    parser.add_argument('--mode', choices=['client', 'publisher'], default='client')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=7070)
    parser.add_argument('--bootstrap', default='http://localhost/bootstrap.php')
    
    args = parser.parse_args()
    
    node = AetheriumNode(mode=args.mode, host=args.host, port=args.port, bootstrap_url=args.bootstrap)
    
    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        logger.info("Shutting down")

if __name__ == "__main__":
    main()
