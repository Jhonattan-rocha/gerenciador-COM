import socket
import time
import serial

try:
        print(f"Conectado a 10.150.0.64:10000")

        # Mensagem de teste
        mensagem = "Teste de comunicacao via COM4\n"

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("10.150.0.64", 10000))

        client_socket.sendall(mensagem.encode())
        # Pequena pausa para garantir envio completo
        
        time.sleep(5)
        
        porta = serial.Serial(port='COM5', baudrate=9600, bytesize=8, parity="E", stopbits=2, timeout=30)
        dados = porta.readall()
        print(dados)

        client_socket.close()

except Exception as e:
    print(f"Erro ao acessar: {e}")
