import time
import serial
import socket

try:
    texto = b'Nada de mais, apenas 1 teste\n'
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("10.150.0.12", 10000))
    
    client.sendall(texto)
    
    time.sleep(2)
    
    saida = serial.serial_for_url(url='loop://', baudrate=9600, bytesize=8, parity="E", stopbits=2, rtscts=False, dsrdtr=False, timeout=5) # Timeout para a abertura

    if saida.is_open:
        print("COM7 aberta para leitura")
    else:
        print("Erro ao abrir COM7")

    print(f"Aberto para leitura: {saida.readable()}")

    inicio_tempo = time.time()
    timeout_leitura = 10 # Esperar no máximo 10 segundos por dados

    dados_recebidos = b'' # Inicializa como bytes vazios

    while time.time() - inicio_tempo < timeout_leitura:
        if saida.in_waiting > 0:
            dados_recebidos = saida.read(saida.in_waiting) # Lê os dados disponíveis
            break # Sai do loop se dados forem recebidos
        time.sleep(0.1) # Espera um pouco e verifica novamente

    print(dados_recebidos) # Imprime os dados recebidos (ou b'' se timeout)

    saida.close()
    print("Porta COM7 fechada!")

except Exception as e:
    print(f"Erro ao acessar: {e}")
