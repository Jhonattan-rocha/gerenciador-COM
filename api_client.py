import requests
import logging

# Obtém o mesmo logger usado no resto do aplicativo
logger = logging.getLogger("SerialApp")

class APIClient:
    """
    Cliente para interagir com o backend de gerenciamento.
    """
    def __init__(self, base_url: str):
        if not base_url.startswith("http"):
            self.base_url = f"http://{base_url}"
        else:
            self.base_url = base_url
        
        # Define um timeout padrão para as requisições
        self.timeout = 15

    def validar_licenca(self, usuario: str, senha: str) -> tuple[bool, str]:
        """
        Valida as credenciais do usuário (licença) no backend.

        Args:
            usuario (str): O nome de usuário para validação.
            senha (str): A senha ou chave de licença.

        Returns:
            tuple[bool, str]: (True, "Mensagem de sucesso") se a licença for válida.
                              (False, "Mensagem de erro") se for inválida ou houver falha.
        """
        if not self.base_url:
            return False, "URL do backend não configurada."
        
        # O endpoint que vamos criar no backend se chamará /api/v1/licenca/validar
        url = f"{self.base_url}/api/v1/licenca/validar"
        
        logger.info(f"Tentando validar licença para o usuário '{usuario}' no endpoint: {url}")

        try:
            response = requests.post(
                url,
                json={"usuario": usuario, "senha": senha},
                timeout=self.timeout
            )

            # Verifica se a resposta foi bem-sucedida (código 2xx)
            if response.status_code == 200:
                logger.info(f"Licença validada com sucesso para o usuário '{usuario}'.")
                return True, "Licença ativada com sucesso."
            
            # Tratamento de erros comuns
            elif response.status_code == 401:
                logger.warning(f"Falha na validação da licença para '{usuario}': Credenciais inválidas.")
                return False, "Usuário ou senha inválidos."
            elif response.status_code == 404:
                 logger.error(f"Erro de validação: Endpoint não encontrado em {url}. Verifique a URL do backend.")
                 return False, "Não foi possível encontrar o servidor de licenças. Verifique a URL."
            else:
                # Outros erros do lado do servidor
                error_msg = response.json().get("detail", "Erro desconhecido do servidor.")
                logger.error(f"Erro do servidor ao validar licença ({response.status_code}): {error_msg}")
                return False, f"Erro no servidor: {error_msg}"

        except requests.exceptions.RequestException as e:
            logger.critical(f"Erro de conexão ao tentar validar licença: {e}")
            return False, "Não foi possível conectar ao servidor de licenças. Verifique sua conexão e a URL do backend."