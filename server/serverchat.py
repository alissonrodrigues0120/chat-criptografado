import socket
import threading
import json
from datetime import datetime

class SimpleChatServer:
    """Servidor central para coordenação dos clientes"""
    
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # {client_name: (connection, public_key)}
        self.messages = {}  # {recipient: [(sender, message_type, data)]}
        self.lock = threading.Lock()
        print(f"[SERVER] Iniciando servidor em {host}:{port}")
    
    def start(self):
        """Inicia o servidor e aceita conexões"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[SERVER] Aguardando conexões...")
        
        while True:
            client_socket, address = self.server_socket.accept()
            print(f"[SERVER] Nova conexão de {address}")
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
    
    def broadcast_online_clients(self):
        """Envia lista atualizada de clientes online para todos"""
        online_clients = list(self.clients.keys())
        print(f"[SERVER] Clientes online: {online_clients}")
        
        for client_name, (client_socket, _) in self.clients.items():
            try:
                client_socket.send(json.dumps({
                    'type': 'online_clients',
                    'clients': online_clients,
                    'sender': 'SERVER'
                }).encode('utf-8'))
            except Exception as e:
                print(f"[SERVER] Erro ao enviar lista para {client_name}: {e}")
    
    def handle_client(self, client_socket):
        """Lida com um cliente conectado"""
        client_name = None
        try:
            # Primeira mensagem deve ser o registro do cliente
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                return
            
            message = json.loads(data)
            if message['type'] == 'register':
                client_name = message['name']
                public_key = message['public_key']
                
                with self.lock:
                    self.clients[client_name] = (client_socket, public_key)
                    print(f"[SERVER] Cliente '{client_name}' registrado")
                
                # Enviar confirmação de registro
                client_socket.send(json.dumps({
                    'type': 'register_success',
                    'message': f'Bem-vindo, {client_name}!',
                    'sender': 'SERVER'
                }).encode('utf-8'))
                
                # Atualizar lista de clientes online para todos
                self.broadcast_online_clients()
                
                # Processar mensagens pendentes para este cliente
                self.process_pending_messages(client_name)
                
                # Loop principal para receber mensagens deste cliente
                self.client_message_loop(client_socket, client_name)
                
        except Exception as e:
            print(f"[SERVER] Erro com cliente {client_name or 'desconhecido'}: {e}")
        finally:
            if client_name:
                with self.lock:
                    if client_name in self.clients:
                        del self.clients[client_name]
                        print(f"[SERVER] Cliente '{client_name}' desconectado")
                self.broadcast_online_clients()
    
    def client_message_loop(self, client_socket, client_name):
        """Loop principal para receber mensagens de um cliente"""
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                message = json.loads(data.decode('utf-8'))
                msg_type = message['type']
                
                if msg_type == 'session_key':
                    # Roteia chave de sessão para o destinatário
                    recipient = message['recipient']
                    self.route_message(client_name, recipient, 'session_key', message['data'])

                elif msg_type == 'get_public_key':
                    # Cliente solicita a chave pública de outro cliente
                    recipient = message.get('recipient')
                    with self.lock:
                        if recipient in self.clients:
                            _, recipient_pub = self.clients[recipient]
                            try:
                                client_socket.send(json.dumps({
                                    'type': 'public_key',
                                    'recipient': recipient,
                                    'data': recipient_pub,
                                    'sender': 'SERVER'
                                }).encode('utf-8'))
                                print(f"[SERVER] Enviando chave pública de {recipient} para {client_name}")
                            except Exception as e:
                                print(f"[SERVER] Erro ao enviar chave pública: {e}")
                        else:
                            client_socket.send(json.dumps({
                                'type': 'public_key_error',
                                'recipient': recipient,
                                'message': 'Recipient not found',
                                'sender': 'SERVER'
                            }).encode('utf-8'))
                
                elif msg_type == 'encrypted_message':
                    # Roteia mensagem criptografada para o destinatário
                    recipient = message['recipient']
                    self.route_message(client_name, recipient, 'encrypted_message', message['data'])
                    
            except Exception as e:
                print(f"[SERVER] Erro no loop de mensagens de {client_name}: {e}")
                break
    
    def process_pending_messages(self, client_name):
        """Processa mensagens pendentes para um cliente específico"""
        with self.lock:
            if client_name in self.messages:
                for message in self.messages[client_name]:
                    sender, msg_type, data = message
                    try:
                        client_socket, _ = self.clients[client_name]
                        client_socket.send(json.dumps({
                            'type': msg_type,
                            'sender': sender,
                            'data': data
                        }).encode('utf-8'))
                        print(f"[SERVER] Mensagem entregue para {client_name} de {sender}")
                    except Exception as e:
                        print(f"[SERVER] Falha ao entregar mensagem: {e}")
                # Limpar mensagens entregues
                del self.messages[client_name]
    
    def route_message(self, sender, recipient, msg_type, data):
        """Roteia mensagens entre clientes"""
        print(f"[SERVER] Roteando {msg_type}: {sender} -> {recipient}")
        with self.lock:
            if recipient in self.clients:
                try:
                    client_socket, _ = self.clients[recipient]
                    client_socket.send(json.dumps({
                        'type': msg_type,
                        'sender': sender,
                        'data': data
                    }).encode('utf-8'))
                    print(f"[SERVER] Mensagem entregue: {sender} -> {recipient}")
                except Exception as e:
                    print(f"[SERVER] Cliente {recipient} offline. Armazenando mensagem.")
                    self.store_pending_message(sender, recipient, msg_type, data)
            else:
                print(f"[SERVER] Destinatário {recipient} não encontrado.")
                self.store_pending_message(sender, recipient, msg_type, data)
    
    def store_pending_message(self, sender, recipient, msg_type, data):
        """Armazena mensagem para entrega futura"""
        with self.lock:
            if recipient not in self.messages:
                self.messages[recipient] = []
            self.messages[recipient].append((sender, msg_type, data))
            print(f"[SERVER] Mensagem armazenada para {recipient} ({len(self.messages[recipient])} total)")

if __name__ == "__main__":
    server = SimpleChatServer()
    server.start()