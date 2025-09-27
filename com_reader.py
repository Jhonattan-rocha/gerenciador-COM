# com_reader.py
import serial
import time
from datetime import datetime

# --- CONFIGURAÇÕES ---
PORTA_LEITURA = 'COM4'      # Porta onde este script vai ler os dados.
BAUDRATE = 9600
ARQUIVO_LOG = 'test_log.txt' # Nome do arquivo para salvar os dados recebidos.
# ---------------------

def main():
    print(f"--- Leitor de Dados da Porta Serial ---")
    print(f"Escutando na porta {PORTA_LEITURA} a {BAUDRATE} baud.")
    print(f"Os dados recebidos serão salvos em '{ARQUIVO_LOG}'.")
    print("Pressione Ctrl+C para sair.")
    
    ser = None
    
    while True: # Loop para tentar reabrir a porta em caso de erro
        try:
            ser = serial.Serial(PORTA_LEITURA, BAUDRATE, timeout=1)
            print(f"\nPorta {PORTA_LEITURA} aberta. Aguardando dados...")
            
            while True:
                try:
                    # Lê uma linha da porta serial (até encontrar um '\n')
                    linha_bytes = ser.readline()
                    
                    if linha_bytes:
                        # Decodifica os bytes para string usando 'cp850'
                        dados_recebidos = linha_bytes.decode('cp850').strip()
                        
                        # Obtém o timestamp atual
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        
                        log_completo = f"[{timestamp}] - {dados_recebidos}"
                        
                        # Imprime no console
                        print(log_completo)
                        
                        # Salva no arquivo de log
                        with open(ARQUIVO_LOG, 'a', encoding='utf-8') as f:
                            f.write(log_completo + '\n')
                            
                except serial.SerialException as e:
                    print(f"\nERRO: A porta serial foi desconectada ou falhou: {e}")
                    print("Tentando reabrir em 5 segundos...")
                    ser.close()
                    time.sleep(5)
                    break # Sai do loop interno para tentar reabrir a porta
                    
        except serial.SerialException as e:
            print(f"ERRO: Não foi possível abrir a porta {PORTA_LEITURA}. Tentando novamente em 5 segundos...")
            print(f"Detalhes: {e}")
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n--- Script interrompido pelo usuário. Fechando a porta. ---")
            break
        finally:
            if ser and ser.is_open:
                ser.close()
    
    print("Script finalizado.")

if __name__ == '__main__':
    main()