from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import struct

class SymmetricEncryption:
    """Criptografia simétrica com implementação manual dos modos CBC e CTR"""
    
    def __init__(self, session_key=None, mode="CBC"):
        self.session_key = session_key
        self.current_mode = mode.upper()
        self.block_size = AES.block_size  # 16 bytes for AES
        
        # For CTR mode - maintain counter for each session
        self.current_counter = None
        self.nonce = None
    
    def set_session_key(self, session_key):
        """Define a chave de sessão usada para cifrar/decifrar"""
        self.session_key = session_key
    
    def set_mode(self, mode):
        """Define o modo de operação (CBC ou CTR)"""
        mode = mode.upper()
        if mode not in ["CBC", "CTR"]:
            raise ValueError("Invalid mode. Use 'CBC' or 'CTR'")
        self.current_mode = mode
        
        # Reiniciar contador para CTR ao trocar de modo
        if mode == "CTR":
            self.nonce = get_random_bytes(8)  # 8 bytes para o nonce
            self.current_counter = 0
    
    def _xor_bytes(self, a, b):
        """Função auxiliar para XOR entre duas sequências de bytes"""
        return bytes(x ^ y for x, y in zip(a, b))
    
    #######################
    # CBC MODE IMPLEMENTATION
    #######################
    
    def encrypt_cbc(self, data):
        """Implementação manual do modo CBC"""
        if not self.session_key:
            raise ValueError("Chave de sessão não definida")

        # 1. Gerar IV aleatório
        iv = get_random_bytes(self.block_size)

        # 2. Aplicar padding para que os dados sejam múltiplos do tamanho do bloco
        padded_data = pad(data, self.block_size, style='pkcs7')

        # 3. Inicializar AES em modo ECB (primitiva)
        cipher = AES.new(self.session_key, AES.MODE_ECB)

        # 4. Implementação manual do CBC
        blocks = [padded_data[i:i + self.block_size]
                  for i in range(0, len(padded_data), self.block_size)]

        previous_block = iv
        encrypted_data = b''

        for block in blocks:
            # XOR do bloco corrente com o bloco anterior cifrado (ou IV no primeiro bloco)
            block_xor = self._xor_bytes(block, previous_block)

            # Cifrar o XOR
            encrypted_block = cipher.encrypt(block_xor)

            # Guardar para a próxima iteração
            previous_block = encrypted_block
            encrypted_data += encrypted_block

        # 5. Retornar IV + dados cifrados (IV pode ser enviado em claro)
        return iv + encrypted_data
    
    def decrypt_cbc(self, encrypted_data):
        """Implementação manual da decifra em modo CBC"""
        if not self.session_key:
            raise ValueError("Chave de sessão não definida")

        if len(encrypted_data) < self.block_size:
            raise ValueError("Dados cifrados muito curtos")

        # 1. Separar IV dos dados cifrados
        iv = encrypted_data[:self.block_size]
        pure_encrypted_data = encrypted_data[self.block_size:]

        # 2. Inicializar AES em ECB para uso como primitiva
        cipher = AES.new(self.session_key, AES.MODE_ECB)

        # 3. Implementação manual do CBC para decifrar
        encrypted_blocks = [pure_encrypted_data[i:i + self.block_size]
                            for i in range(0, len(pure_encrypted_data), self.block_size)]

        previous_block = iv
        decrypted_data = b''

        for encrypted_block in encrypted_blocks:
            # Decifrar o bloco
            decrypted_block = cipher.decrypt(encrypted_block)

            # XOR com o bloco anterior cifrado (ou IV para o primeiro bloco)
            original_block = self._xor_bytes(decrypted_block, previous_block)

            # Guardar para a próxima iteração
            previous_block = encrypted_block
            decrypted_data += original_block

        # 4. Remover padding PKCS#7
        return unpad(decrypted_data, self.block_size, style='pkcs7')
    
    #######################
    # CTR MODE IMPLEMENTATION
    #######################
    
    def _generate_ctr_stream(self, nonce, initial_counter, size):
        """Gera fluxo de bytes para o modo CTR"""
        if not self.session_key:
            raise ValueError("Chave de sessão não definida")

        cipher = AES.new(self.session_key, AES.MODE_ECB)
        stream = b''
        counter = initial_counter

        # Calcular quantos blocos são necessários
        blocks_needed = (size + self.block_size - 1) // self.block_size

        for i in range(blocks_needed):
            # Construir bloco do contador: nonce (64 bits) + counter (64 bits)
            counter_block = nonce + struct.pack('>Q', counter)  # Big-endian 64 bits

            # Cifrar o bloco do contador para gerar parte do fluxo
            stream_block = cipher.encrypt(counter_block)
            stream += stream_block

            counter += 1

        # Retornar somente os bytes necessários
        return stream[:size]
    
    def encrypt_ctr(self, data):
        """Implementação manual do modo CTR"""
        if not self.session_key:
            raise ValueError("Chave de sessão não definida")

        # Gerar nonce aleatório caso ainda não exista
        if not self.nonce:
            self.nonce = get_random_bytes(8)  # 64 bits para nonce

        # Incrementar contador para esta mensagem
        self.current_counter += 1
        initial_counter = self.current_counter

        # Gerar fluxo do mesmo tamanho dos dados
        stream = self._generate_ctr_stream(self.nonce, initial_counter, len(data))

        # XOR entre dados e fluxo para cifrar
        encrypted_data = self._xor_bytes(data, stream)

        # Retornar nonce + contador inicial + dados cifrados
        return self.nonce + struct.pack('>Q', initial_counter) + encrypted_data
    
    def decrypt_ctr(self, encrypted_data):
        """Implementação manual da decifra em modo CTR"""
        if not self.session_key:
            raise ValueError("Chave de sessão não definida")

        if len(encrypted_data) < 16:  # 8 bytes nonce + 8 bytes counter
            raise ValueError("Dados cifrados muito curtos")

        # Separar nonce, contador e dados cifrados
        nonce = encrypted_data[:8]
        initial_counter = struct.unpack('>Q', encrypted_data[8:16])[0]
        pure_data = encrypted_data[16:]

        # Gerar o mesmo fluxo usado na cifragem
        stream = self._generate_ctr_stream(nonce, initial_counter, len(pure_data))

        # XOR para recuperar os dados originais
        return self._xor_bytes(pure_data, stream)
    
   
    
    def encrypt(self, message):
        """Método público para cifrar usando o modo atual"""
        data = message.encode('utf-8')

        if self.current_mode == "CBC":
            return self.encrypt_cbc(data)
        elif self.current_mode == "CTR":
            return self.encrypt_ctr(data)
        else:
            raise ValueError(f"Modo não suportado: {self.current_mode}")
    
    def decrypt(self, encrypted_data):
        """Método público para decifrar usando o modo atual"""
        if self.current_mode == "CBC":
            decrypted_data = self.decrypt_cbc(encrypted_data)
        elif self.current_mode == "CTR":
            decrypted_data = self.decrypt_ctr(encrypted_data)
        else:
            raise ValueError(f"Modo não suportado: {self.current_mode}")

        return decrypted_data.decode('utf-8')