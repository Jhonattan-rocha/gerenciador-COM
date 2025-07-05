import requests
import logging

logger = logging.getLogger("SerialApp")

class APIClient:
    """
    Cliente para interagir com o backend de gerenciamento.
    Agora gerencia a autenticação via token JWT.
    """
    def __init__(self, base_url: str):
        if not base_url.startswith("http"):
            self.base_url = f"http://{base_url}"
        else:
            self.base_url = base_url
        
        self.timeout = 15
        self.token = None  # Armazenará o token JWT

    def _get_auth_header(self) -> dict:
        """ Monta o cabeçalho de autorização se o token existir. """
        if not self.token:
            raise ValueError("Token de autenticação não foi definido.")
        return {"Authorization": f"Bearer {self.token}"}

    def obter_token(self, usuario: str, senha: str) -> tuple[bool, str]:
        """
        Obtém um token de acesso do backend.

        Returns:
            tuple[bool, str]: (True, "Mensagem de sucesso") se o login for bem-sucedido.
                              (False, "Mensagem de erro") se falhar.
        """
        url = f"{self.base_url}/api/v1/login/access-token"
        logger.info(f"Obtendo token para o usuário '{usuario}' em {url}")

        try:
            # O endpoint de token do FastAPI espera dados de formulário
            data = {"username": usuario, "password": senha}
            response = requests.post(url, data=data, timeout=self.timeout)

            if response.status_code == 200:
                self.token = response.json().get("access_token")
                logger.info(f"Token obtido com sucesso para '{usuario}'.")
                return True, "Login realizado com sucesso."
            
            error_msg = response.json().get("detail", "Credenciais inválidas.")
            logger.warning(f"Falha ao obter token para '{usuario}': {error_msg}")
            return False, f"Falha no login: {error_msg}"

        except requests.exceptions.RequestException as e:
            logger.critical(f"Erro de conexão ao obter token: {e}")
            return False, "Não foi possível conectar ao servidor de autenticação."

    def validar_licenca(self) -> tuple[bool, str]:
        """
        Valida a licença no backend usando o token de acesso armazenado.
        
        Returns:
            tuple[bool, str]: (True, "Mensagem de sucesso") se a licença for válida.
                              (False, "Mensagem de erro") se for inválida ou houver falha.
        """
        if not self.token:
            return False, "Autenticação necessária. Faça o login primeiro."

        url = f"{self.base_url}/api/v1/licenca/validar"
        logger.info(f"Validando licença no endpoint: {url}")

        try:
            headers = self._get_auth_header()
            response = requests.post(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                success_msg = response.json().get("detail", "Licença validada.")
                logger.info(f"Validação de licença bem-sucedida: {success_msg}")
                return True, success_msg
            
            error_msg = response.json().get("detail", "Licença inválida ou expirada.")
            logger.error(f"Erro do servidor ao validar licença ({response.status_code}): {error_msg}")
            return False, f"Erro na validação: {error_msg}"

        except (requests.exceptions.RequestException, ValueError) as e:
            logger.critical(f"Erro de conexão ou autenticação ao validar licença: {e}")
            return False, "Não foi possível conectar ao servidor de licenças."