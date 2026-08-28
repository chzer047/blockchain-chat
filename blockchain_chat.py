"""
Núcleo do chat criptografado em blockchain local.

Identidade pseudônima via RSA-2048.
Mensagens e nicknames cifrados com AES-256-GCM + chave derivada do código de sala (PBKDF2).
Cada mensagem é um bloco com hash SHA-256 encadeado e assinatura RSA-PSS.
"""

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

CHAINS_DIR = Path("chat_chains")
CHAINS_DIR.mkdir(exist_ok=True)


# ─── Identidade ───────────────────────────────────────────────────────────────

def gerar_par_chaves() -> tuple[bytes, bytes]:
    """Gera par RSA-2048. Retorna (private_pem, public_pem)."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def calcular_wallet(public_pem: bytes) -> str:
    """Endereço pseudônimo = primeiros 20 hex do SHA-256 da chave pública."""
    return hashlib.sha256(public_pem).hexdigest()[:20].upper()


def validar_chave_privada(pem_bytes: bytes) -> Optional[tuple[bytes, bytes]]:
    """Valida PEM de chave privada. Retorna (private_pem, public_pem) ou None."""
    try:
        key = load_pem_private_key(pem_bytes, password=None, backend=default_backend())
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem
    except Exception:
        return None


# ─── Criptografia ─────────────────────────────────────────────────────────────

def derivar_chave_sala(room_code: str) -> bytes:
    """Deriva AES-256 do código de sala via PBKDF2-SHA256 (200k iterações)."""
    salt = hashlib.sha256(("SALA-V1:" + room_code).encode()).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(room_code.encode())


def cifrar(aes_key: bytes, plaintext: str) -> str:
    """AES-256-GCM. Retorna base64(nonce[12] + ciphertext)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def decifrar(aes_key: bytes, blob_b64: str) -> Optional[str]:
    """Decifra AES-256-GCM. Retorna None se chave errada ou dados corrompidos."""
    try:
        data = base64.b64decode(blob_b64)
        nonce, ct = data[:12], data[12:]
        return AESGCM(aes_key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return None


def _assinar(private_pem: bytes, payload: str) -> str:
    key = load_pem_private_key(private_pem, password=None, backend=default_backend())
    sig = key.sign(
        payload.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def _verificar(public_pem_str: str, payload: str, sig_b64: str) -> bool:
    try:
        key = load_pem_public_key(public_pem_str.encode(), backend=default_backend())
        key.verify(
            base64.b64decode(sig_b64),
            payload.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ─── Blockchain ───────────────────────────────────────────────────────────────

def _hash_bloco(index: int, ts: float, sender: str, msg_cifrada: str, prev_hash: str) -> str:
    raw = f"{index}{ts:.6f}{sender}{msg_cifrada}{prev_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _genesis() -> Dict[str, Any]:
    return {
        "index": 0,
        "timestamp": 0.0,
        "sender": "GENESIS",
        "msg_cifrada": "",
        "nick_cifrado": "",
        "signature": "",
        "public_key_pem": "",
        "prev_hash": "0" * 64,
        "hash": hashlib.sha256(b"genesis-blockchain-chat-v1").hexdigest(),
    }


def _caminho_sala(room_code: str) -> Path:
    nome = hashlib.sha256(("CHAIN-V1:" + room_code).encode()).hexdigest()[:24]
    return CHAINS_DIR / f"{nome}.json"


def _carregar_chain(room_code: str) -> List[Dict[str, Any]]:
    path = _caminho_sala(room_code)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _salvar_chain(room_code: str, chain: List[Dict[str, Any]]) -> None:
    path = _caminho_sala(room_code)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(chain, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def info_sala(room_code: str) -> Dict[str, int]:
    chain = _carregar_chain(room_code)
    return {"altura": len(chain), "mensagens": max(0, len(chain) - 1)}


def enviar_mensagem(
    room_code: str,
    private_pem: bytes,
    public_pem: bytes,
    wallet: str,
    texto: str,
    nickname: str = "",
) -> None:
    """
    Cifra texto e nickname e adiciona um bloco à blockchain da sala.
    O nickname é cifrado com a chave da sala — invisível sem o código correto.
    """
    chain = _carregar_chain(room_code)
    if not chain:
        chain = [_genesis()]

    aes_key      = derivar_chave_sala(room_code)
    msg_cifrada  = cifrar(aes_key, texto)
    nick_cifrado = cifrar(aes_key, nickname.strip()[:32]) if nickname.strip() else ""

    prev      = chain[-1]
    index     = prev["index"] + 1
    ts        = time.time()
    prev_hash = prev["hash"]

    payload    = f"{index}{ts:.6f}{wallet}{msg_cifrada}{prev_hash}"
    sig        = _assinar(private_pem, payload)
    bloco_hash = _hash_bloco(index, ts, wallet, msg_cifrada, prev_hash)

    chain.append({
        "index":          index,
        "timestamp":      ts,
        "sender":         wallet,
        "msg_cifrada":    msg_cifrada,
        "nick_cifrado":   nick_cifrado,
        "signature":      sig,
        "public_key_pem": public_pem.decode(),
        "prev_hash":      prev_hash,
        "hash":           bloco_hash,
    })
    _salvar_chain(room_code, chain)


def ler_mensagens(room_code: str) -> List[Dict[str, Any]]:
    """Decifra e retorna todas as mensagens da sala."""
    chain = _carregar_chain(room_code)
    if len(chain) <= 1:
        return []

    aes_key   = derivar_chave_sala(room_code)
    resultado = []

    for bloco in chain[1:]:
        texto    = decifrar(aes_key, bloco["msg_cifrada"])
        nickname = decifrar(aes_key, bloco.get("nick_cifrado", "")) or ""
        payload  = (
            f"{bloco['index']}{bloco['timestamp']:.6f}"
            f"{bloco['sender']}{bloco['msg_cifrada']}{bloco['prev_hash']}"
        )
        valido = _verificar(
            bloco.get("public_key_pem", ""),
            payload,
            bloco.get("signature", ""),
        )
        resultado.append({
            "index":     bloco["index"],
            "timestamp": bloco["timestamp"],
            "sender":    bloco["sender"],
            "nickname":  nickname,
            "texto":     texto if texto is not None else "[chave de sala incorreta]",
            "valido":    valido,
            "hash":      bloco["hash"][:12],
        })

    return resultado
