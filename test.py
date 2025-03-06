import socket
import time

try:
        print(f"Conectado a 10.0.0.107:9000")

        # Mensagem de teste
        mensagem = "Teste de comunicação via COM4\n"

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("10.0.0.107", 9000))

        client_socket.sendall(mensagem.encode())
        # Pequena pausa para garantir envio completo
        
        time.sleep(1)

        client_socket.close()

except Exception as e:
    print(f"Erro ao acessar: {e}")
