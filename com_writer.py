# com_writer.py
import serial
import time
import random

# --- CONFIGURAÇÕES ---
PORTA_ESCRITA = 'COM5'  # Porta onde este script vai escrever os dados.
BAUDRATE = 9600
# ---------------------

def gerar_dados(numero_base):
    """Gera uma string de dados no formato especificado."""
    # Gera uma string como: "1 1 1 1 1 1 1 1 1 1 11"
    dados = [str(numero_base)] * 10
    dados.append(str(numero_base) * 2)
    return " ".join(dados)

def main():
    print(f"--- Escritor de Dados para a Porta Serial ---")
    print(f"Tentando abrir a porta {PORTA_ESCRITA} a {BAUDRATE} baud.")
    
    ser = None
    numero_sequencia = 1
    
    try:
        ser = serial.Serial(PORTA_ESCRITA, BAUDRATE, timeout=2)
        print(f"Porta {PORTA_ESCRITA} aberta com sucesso.")
        
        while True:
            print(f"\n--- Iniciando nova rajada de dados com a sequência: {numero_sequencia} ---")
            dados_para_enviar = gerar_dados(numero_sequencia)
            
            # Envia a mesma sequência várias vezes por 20 segundos
            tempo_inicio_rajada = time.time()
            while time.time() - tempo_inicio_rajada < 20:
                
                # Codifica a string para bytes usando 'cp850' e adiciona uma quebra de linha
                dados_bytes = (dados_para_enviar + '\n').encode('cp850')
                
                try:
                    ser.write(dados_bytes)
                    ser.flush() # Garante que os dados sejam enviados
                    print(f"Enviado: '{dados_para_enviar}'")
                except serial.SerialException as e:
                    print(f"Erro ao escrever na porta serial: {e}")
                    # Tenta reabrir a porta
                    ser.close()
                    time.sleep(2)
                    ser.open()
                    print("Tentando reabrir a porta...")

                # Espera um tempo variável para simular um dispositivo real
                tempo_espera = random.uniform(0.5, 2.0)
                time.sleep(tempo_espera)

            # Muda a sequência para a próxima rajada
            numero_sequencia += 1
            if numero_sequencia > 9:
                numero_sequencia = 1 # Reinicia para 1

    except serial.SerialException as e:
        print(f"ERRO: Não foi possível abrir a porta {PORTA_ESCRITA}. Verifique se a porta existe e não está em uso.")
        print(f"Detalhes: {e}")
    except KeyboardInterrupt:
        print("\n--- Script interrompido pelo usuário. Fechando a porta. ---")
    finally:
        if ser and ser.is_open:
            ser.close()
            print(f"Porta {PORTA_ESCRITA} fechada.")

if __name__ == '__main__':
    main()