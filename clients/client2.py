import socket
import threading
import json
import time
import sys
import os

# Garantir que o diretório raiz do projeto esteja no sys.path para permitir
# imports absolutos como `from criptography...` mesmo quando o script for
# executado diretamente.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from criptography.assimetric import AsymmetricKeyManager
from criptography.protocol_keys import KeyExchangeProtocol
from criptography.simetric import SymmetricEncryption

class ChatClient:
    """Cliente de chat seguro"""
    
    def __init__(self, name, server_host='localhost', server_port=5000):
        self.name = name
        self.server_host = server_host
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key = None
        self.recipient = None
        self.online_clients = []
        # Pending public keys requested from server: recipient -> public_key_pem or None
        self.pending_public_keys = {}
        
        # Inicializar sistemas criptográficos
        self.key_manager = AsymmetricKeyManager()
        self.key_exchange = KeyExchangeProtocol(self.key_manager)
        self.symmetric_crypto = SymmetricEncryption(mode="CBC")
        
        print(f"[{self.name}] Sistema criptográfico inicializado")
    
    def connect_to_server(self):
        """Conecta ao servidor e se registra"""
        try:
            self.client_socket.connect((self.server_host, self.server_port))
            
            # Registrar no servidor com chave pública
            registration = {
                'type': 'register',
                'name': self.name,
                'public_key': self.key_manager.export_public_key()
            }
            self.client_socket.send(json.dumps(registration).encode('utf-8'))
            print(f"[{self.name}] Registrando no servidor...")
            
            # Aguardar confirmação de registro
            response = self.client_socket.recv(4096).decode('utf-8')
            if not response:
                print(f"[{self.name}] Falha na conexão com o servidor")
                return False
            
            response_data = json.loads(response)
            if response_data['type'] == 'register_success':
                print(f"[{self.name}] Registro bem-sucedido: {response_data['message']}")
            
            # Iniciar thread para receber mensagens
            threading.Thread(target=self.receive_messages, daemon=True).start()
            
            # Aguardar lista inicial de clientes online
            time.sleep(1)
            return True
        except Exception as e:
            print(f"[{self.name}] Erro ao conectar: {e}")
            return False
    
    def receive_messages(self):
        """Thread para receber mensagens do servidor"""
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    print(f"[{self.name}] Conexão com servidor perdida")
                    break

                # Debug: mostrar o payload cru recebido para inspecionar problemas
                raw = data.decode('utf-8', errors='replace')

                # Tentar decodificar JSON de forma robusta
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError as e:
                    print(f"\n[{self.name}] ERRO ao decodificar JSON: {e}; raw={raw}")
                    continue

                msg_type = message.get('type')
                sender = message.get('sender', '<unknown>')
                data_content = message.get('data', None)

                if not msg_type:
                    print(f"\n[{self.name}] Mensagem sem campo 'type' recebida: {message}")
                    continue
                
                if msg_type == 'online_clients':
                    # O servidor envia o campo 'clients' (lista) em vez de 'data'
                    online = message.get('clients') or data_content
                    if not isinstance(online, list):
                        print(f"\n[{self.name}] ERRO: formato inesperado para 'online_clients': {online}")
                    else:
                        self.online_clients = online
                        print(f"\n[{self.name}] Clientes online atualizados: {', '.join(self.online_clients)}")
                    print(f"{self.name}> ", end='', flush=True)
                elif msg_type == 'session_key':
                    # Recebeu chave de sessão cifrada de outro cliente
                    print(f"\n[{self.name}] Recebendo chave de sessão de {sender}...")
                    if isinstance(data_content, str):
                        try:
                            encrypted = bytes.fromhex(data_content)
                        except Exception:
                            print(f"\n[{self.name}] ERRO: session_key não está em hex válido: {data_content}")
                            continue
                    else:
                        encrypted = data_content

                    session_key = self.key_exchange.process_received_session_key(encrypted)

                    if session_key:
                        self.session_key = session_key
                        self.symmetric_crypto.set_session_key(session_key)
                        self.recipient = sender
                        print(f"[{self.name}] Chave de sessão estabelecida com {sender}!")
                        print(f"{self.name}> ", end='', flush=True)

                elif msg_type == 'public_key':
                    recipient_name = message.get('recipient')
                    public_key_pem = message.get('data')
                    if recipient_name:
                        self.pending_public_keys[recipient_name] = public_key_pem
                        print(f"\n[{self.name}] Recebida chave pública de {recipient_name}")
                        print(f"{self.name}> ", end='', flush=True)

                elif msg_type == 'public_key_error':
                    recipient_name = message.get('recipient')
                    print(f"\n[{self.name}] ERRO: não foi possível obter chave pública de {recipient_name}: {message.get('message')}")
                    self.pending_public_keys.pop(recipient_name, None)
                    print(f"{self.name}> ", end='', flush=True)
                elif msg_type == 'encrypted_message':
                    # Recebeu mensagem criptografada
                    if not self.session_key:
                        print(f"\n[{self.name}] ERRO: Mensagem recebida sem chave de sessão estabelecida!")
                        print(f"{self.name}> ", end='', flush=True)
                        continue
                    
                    try:
                        decrypted_message = self.symmetric_crypto.decrypt(bytes.fromhex(data_content))
                        print(f"\n[{sender}] {decrypted_message}")
                        print(f"{self.name}> ", end='', flush=True)
                    except Exception as e:
                        print(f"\n[{self.name}] ERRO ao descriptografar mensagem de {sender}: {e}")
                        print(f"{self.name}> ", end='', flush=True)
                
            except Exception as e:
                print(f"\n[{self.name}] Erro ao receber mensagem: {e}")
                print(f"{self.name}> ", end='', flush=True)
    
    def establish_session_with(self, recipient):
        """Estabelece sessão segura com destinatário"""
        if recipient not in self.online_clients:
            print(f"[{self.name}] ERRO: Cliente '{recipient}' não está online")
            return False
        print(f"[{self.name}] Obtendo chave pública de {recipient}...")

        # Solicitar chave pública ao servidor
        self.pending_public_keys[recipient] = None
        self.client_socket.send(json.dumps({
            'type': 'get_public_key',
            'recipient': recipient
        }).encode('utf-8'))

        # Aguardar resposta por alguns segundos
        wait_time = 5.0
        interval = 0.1
        waited = 0.0
        while waited < wait_time:
            pk = self.pending_public_keys.get(recipient)
            if pk:
                break
            time.sleep(interval)
            waited += interval

        pk = self.pending_public_keys.get(recipient)
        if not pk:
            print(f"[{self.name}] ERRO: tempo esgotado ao obter chave pública de {recipient}")
            return False

        # Preparar chave de sessão: retornará (encrypted_session_key, session_key)
        try:
            encrypted_session_key, session_key = self.key_exchange.prepare_session_key(pk)
        except Exception as e:
            print(f"[{self.name}] ERRO ao preparar chave de sessão: {e}")
            return False

        # Enviar chave de sessão cifrada ao destinatário (hex para transporte)
        self.client_socket.send(json.dumps({
            'type': 'session_key',
            'recipient': recipient,
            'data': encrypted_session_key.hex()
        }).encode('utf-8'))

        # Definir localmente a chave de sessão
        self.session_key = session_key
        self.symmetric_crypto.set_session_key(session_key)
        self.recipient = recipient

        print(f"[{self.name}] Chave de sessão estabelecida com {recipient} (iniciador)")
        return True
    
    def send_message(self, message):
        """Envia mensagem para o destinatário atual"""
        if not self.recipient:
            print(f"[{self.name}] ERRO: Nenhum destinatário selecionado. Use 'connect <nome>' primeiro.")
            return False
        
        if not self.session_key:
            print(f"[{self.name}] Sessão não estabelecida com {self.recipient}. Estabelecendo sessão...")
            if not self.establish_session_with(self.recipient):
                return False
        
        try:
            # Criptografar mensagem
            encrypted_message = self.symmetric_crypto.encrypt(message)
            
            # Enviar mensagem criptografada via servidor
            self.client_socket.send(json.dumps({
                'type': 'encrypted_message',
                'recipient': self.recipient,
                'data': encrypted_message.hex()  # Converter para hex para transporte seguro
            }).encode('utf-8'))
            
            print(f"[{self.name}] Mensagem enviada para {self.recipient}")
            return True
        except Exception as e:
            print(f"[{self.name}] ERRO ao enviar mensagem: {e}")
            return False
    
    def list_online_clients(self):
        """Lista clientes online"""
        if not self.online_clients:
            print(f"[{self.name}] Nenhum cliente online no momento")
        else:
            print(f"[{self.name}] Clientes online: {', '.join(self.online_clients)}")
    
    def set_recipient(self, recipient):
        """Define o destinatário atual"""
        if recipient in self.online_clients:
            self.recipient = recipient
            print(f"[{self.name}] Destinatário definido: {recipient}")
            return True
        else:
            print(f"[{self.name}] Cliente '{recipient}' não está online")
            return False

if __name__ == "__main__":
    # Verificar argumentos
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = "Bob"
    
    # Inicializar cliente
    client = ChatClient(name)
    
    if not client.connect_to_server():
        print(f"[{name}] Falha ao conectar com o servidor. Encerrando...")
        sys.exit(1)
    
    print(f"\n=== CLIENTE ({name}) INICIADO ===")
    print("Comandos disponíveis:")
    print("- connect <nome>: Conectar-se a um cliente")
    print("- list: Listar clientes online")
    print("- mode: Alternar entre modos CBC e CTR")
    print("- exit: Sair do chat")
    print(f"\n{name}> ", end='', flush=True)
    
    while True:
        try:
            command = input().strip()
            
            if command.lower() == 'exit':
                print(f"[{name}] Encerrando conexão...")
                break
            elif command.lower() == 'list':
                client.list_online_clients()
            elif command.startswith('connect '):
                recipient = command.split(' ', 1)[1]
                client.set_recipient(recipient)
            elif command.lower() == 'mode':
                current_mode = client.symmetric_crypto.current_mode
                new_mode = "CTR" if current_mode == "CBC" else "CBC"
                client.symmetric_crypto.set_mode(new_mode)
                print(f"[{name}] Modo alterado para: {new_mode}")
            elif command and client.recipient:
                client.send_message(command)
            elif command:
                print(f"[{name}] Selecione um destinatário primeiro com 'connect <nome>'")
            
            print(f"{name}> ", end='', flush=True)
        except KeyboardInterrupt:
            print(f"\n[{name}] Encerrando por solicitação do usuário...")
            break
        except Exception as e:
            print(f"[{name}] Erro: {e}")
            print(f"{name}> ", end='', flush=True)
    
    client.client_socket.close()
    print(f"[{name}] Conexão encerrada")