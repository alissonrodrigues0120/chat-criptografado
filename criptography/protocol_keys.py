class KeyExchangeProtocol:
    """Class to manage the key exchange protocol"""
    
    def __init__(self, key_manager):
        self.manager = key_manager
        self.session_key = None
        self.recipient_public_key = None
    
    def prepare_session_key(self, recipient_public_key_pem):
        # Importar chave pública do destinatário
        self.recipient_public_key = self.manager.import_public_key(
            recipient_public_key_pem
        )
        
        # Gerar chave de sessão simétrica
        session_key = self.manager.generate_session_key()
        
        # Criptografar chave de sessão com chave pública do destinatário
        encrypted_session_key = self.manager.encrypt_with_public_key(
            session_key, 
            self.recipient_public_key
        )
        
        # Armazenar chave de sessão localmente
        self.session_key = session_key
        
        return encrypted_session_key, session_key
    
    def process_received_session_key(self, encrypted_session_key):
        # Aceitar tanto uma chave de sessão cifrada com RSA quanto uma
        # chave de sessão enviada em claro (hex) para fins de simulação.
        try:
            # Se for string (hex), converter para bytes
            if isinstance(encrypted_session_key, str):
                try:
                    encrypted_session_key = bytes.fromhex(encrypted_session_key)
                except Exception:
                    print(f"[Error] session_key recebido não é hex válido: {encrypted_session_key}")
                    return None

            # Primeiro, tentar descriptografar como RSA (fluxo real)
            try:
                self.session_key = self.manager.decrypt_with_private_key(
                    encrypted_session_key
                )
                return self.session_key
            except ValueError as e:
                # Não era um ciphertext RSA --- pode ser a chave de sessão em claro
                # Verificar se o tamanho corresponde a uma chave AES válida
                if isinstance(encrypted_session_key, (bytes, bytearray)) and len(encrypted_session_key) in (16, 24, 32):
                    self.session_key = bytes(encrypted_session_key)
                    return self.session_key
                print(f"[Error] Failed to decrypt session key: {e}")
                return None
        except Exception as e:
            print(f"[Error] Error on process of the session_key: {e}")
            return None
    
    def get_session_key(self):
        """Retorna a chave de sessão simétrica atual"""
        return self.session_key
    
    def get_recipient_public_key(self):
        """Retorna a chave pública do destinatário"""
        return self.recipient_public_key