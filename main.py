import html
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel


def obter_banco() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        """CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL, is_admin INTEGER NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE comentarios (
            id INTEGER PRIMARY KEY, autor TEXT NOT NULL, conteudo TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE campanhas (
            id INTEGER PRIMARY KEY, titulo TEXT NOT NULL, meta REAL NOT NULL
        )"""
    )
    conn.executemany(
        "INSERT INTO usuarios (nome, email, senha, is_admin) VALUES (?, ?, ?, ?)",
        [
            ("Administradora", "admin@hubsolidario.org", "segredo_admin_123", 1),
            ("Voluntário Lucas", "lucas@voluntariado.org", "senha_lucas_456", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO campanhas (titulo, meta) VALUES (?, ?)",
        [("Cestas básicas", 5000.0), ("Material escolar", 2500.0)],
    )
    conn.commit()
    return conn


db = obter_banco()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    db.close()


app = FastAPI(title="Hub Solidário — Laboratório OWASP", lifespan=lifespan)


class RequisicaoLogin(BaseModel):
    email: str
    senha: str


class RequisicaoComentario(BaseModel):
    autor: str
    conteudo: str


def _usuario_dict(row: tuple) -> dict:
    return {"id": row[0], "nome": row[1], "email": row[2], "is_admin": bool(row[3]), "status": "Autenticado com sucesso"}


def _autenticar(dados: RequisicaoLogin, *, vulneravel: bool) -> dict:
    cursor = db.cursor()
    if vulneravel:
        query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
        cursor.execute(query)
    else:
        cursor.execute(
            "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?",
            (dados.email, dados.senha),
        )
    usuario = cursor.fetchone()
    if usuario is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    return _usuario_dict(usuario)


@app.post("/vulneravel/login")
def login_vulneravel(dados: RequisicaoLogin):
    return _autenticar(dados, vulneravel=True)


@app.post("/seguro/login")
def login_seguro(dados: RequisicaoLogin):
    return _autenticar(dados, vulneravel=False)


def _salvar_comentario(dados: RequisicaoComentario, *, seguro: bool) -> dict:
    autor, conteudo = dados.autor, dados.conteudo
    if seguro:
        autor, conteudo = html.escape(autor.strip()), html.escape(conteudo.strip())
    db.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (autor, conteudo))
    db.commit()
    return {"autor": autor, "conteudo": conteudo, "aviso": "Comentário higienizado com sucesso" if seguro else "Comentário registrado sem higienização"}


@app.post("/vulneravel/comentarios")
def comentar_vulneravel(dados: RequisicaoComentario):
    return _salvar_comentario(dados, seguro=False)


@app.post("/seguro/comentarios")
def comentar_seguro(dados: RequisicaoComentario):
    return _salvar_comentario(dados, seguro=True)


def _buscar_campanhas(termo: str, *, vulneravel: bool) -> list[dict]:
    cursor = db.cursor()
    if vulneravel:
        cursor.execute(f"SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE '%{termo}%'")
    else:
        cursor.execute("SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE ?", (f"%{termo}%",))
    return [{"id": row[0], "titulo": row[1], "meta": row[2]} for row in cursor.fetchall()]


@app.get("/vulneravel/campanhas/buscar")
def buscar_campanhas_vulneravel(termo: str = Query(default="")):
    return {"campanhas": _buscar_campanhas(termo, vulneravel=True)}


@app.get("/seguro/campanhas/buscar")
def buscar_campanhas_seguro(termo: str = Query(default="")):
    return {"campanhas": _buscar_campanhas(termo, vulneravel=False)}
