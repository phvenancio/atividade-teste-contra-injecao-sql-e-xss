import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)

@pytest.mark.security
def test_demonstracao_sql_injection_no_login_vulneravel():
    payload = {"email": "admin@hubsolidario.org' --", "senha": "incorreta"}
    resposta = cliente.post("/vulneravel/login", json=payload)
    assert resposta.status_code == 200
    assert resposta.json()["is_admin"] is True


@pytest.mark.security
def test_login_seguro_rejeita_sql_injection():
    payload = {"email": "admin@hubsolidario.org' --", "senha": "incorreta"}
    resposta = cliente.post("/seguro/login", json=payload)
    assert resposta.status_code == 401
    assert "traceback" not in resposta.text.lower()


@pytest.mark.security
def test_demonstracao_xss_reflete_payload_no_endpoint_vulneravel():
    payload = {"autor": "Atacante", "conteudo": "<script>alert('XSS')</script>"}
    resposta = cliente.post("/vulneravel/comentarios", json=payload)
    assert resposta.status_code == 200
    assert resposta.json()["conteudo"] == payload["conteudo"]


@pytest.mark.security
def test_comentario_seguro_escapa_payload_xss():
    
    payload = {"autor": " Atacante ", "conteudo": "<script>alert('XSS')</script>"}
    
    resposta = cliente.post("/seguro/comentarios", json=payload)
    
    assert resposta.status_code == 200
    assert resposta.json()["conteudo"] == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"


@pytest.mark.security
def test_demonstracao_union_select_expoe_dados_de_usuarios():
    payload = "%' UNION SELECT id, email, senha FROM usuarios -- "
    resposta = cliente.get("/vulneravel/campanhas/buscar", params={"termo": payload})
    assert resposta.status_code == 200
    linhas = resposta.json()["campanhas"]
    assert any(linha["titulo"] == "admin@hubsolidario.org" for linha in linhas)
    assert any(linha["meta"] == "segredo_admin_123" for linha in linhas)


@pytest.mark.security
def test_busca_segura_trata_union_como_texto_literal():
    
    payload = "%' UNION SELECT id, email, senha FROM usuarios -- "
    
    resposta = cliente.get("/seguro/campanhas/buscar", params={"termo": payload})
    
    assert resposta.status_code == 200
    assert resposta.json()["campanhas"] == []


@pytest.mark.security
@pytest.mark.parametrize(
    "payload",
    ["<img src=x onerror=alert(1)>", '<svg onload="alert(1)">'],
)
def test_comentario_seguro_escapa_vetores_xss_em_atributos(payload):
    
    corpo = {"autor": "Atacante", "conteudo": payload}
    
    resposta = cliente.post("/seguro/comentarios", json=corpo)
    
    assert resposta.status_code == 200
    assert "<img" not in resposta.json()["conteudo"]
    assert "<svg" not in resposta.json()["conteudo"]
    assert "&lt;" in resposta.json()["conteudo"]
