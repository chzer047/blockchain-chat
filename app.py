import hashlib
import html
import time
from datetime import datetime

import streamlit as st

from blockchain_chat import (
    calcular_wallet,
    enviar_mensagem,
    gerar_par_chaves,
    info_sala,
    ler_mensagens,
    validar_chave_privada,
)

st.set_page_config(
    page_title="Chat Seguro",
    page_icon="🔐",
    layout="wide",
)

# ─── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stSidebar"] { min-width: 290px; max-width: 320px; }
[data-testid="stForm"]    { border: none !important; padding: 0 !important; }

/* Container principal do chat */
.chat-wrapper {
    position: relative;
    height: 540px;
    border-radius: 12px;
    overflow: hidden;
    background: #0b141a;
}

/* Marca d'água GAT VI */
.chat-bg {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 0;
}
.chat-bg-text {
    font-size: 80px;
    font-weight: 900;
    font-family: 'Arial Black', Arial, sans-serif;
    color: rgba(255,255,255,0.035);
    letter-spacing: 10px;
    transform: rotate(-25deg);
    white-space: nowrap;
    user-select: none;
}

/* Área de scroll das mensagens */
.chat-scroll {
    position: absolute;
    inset: 0;
    overflow-y: scroll;
    overflow-x: hidden;
    padding: 10px 12px 16px;
    z-index: 1;
    scroll-behavior: smooth;
}

/* Clearfix */
.chat-scroll::after { content: ""; display: table; clear: both; }

/* Bolhas — próprias */
.bown {
    background: #005c4b;
    color: #e9edef;
    border-radius: 7.5px 7.5px 0 7.5px;
    padding: 6px 9px 22px 9px;
    margin: 2px 0;
    max-width: 67%;
    float: right;
    clear: both;
    word-wrap: break-word;
    line-height: 1.5;
    position: relative;
    box-shadow: 0 1px 2px rgba(0,0,0,.4);
}

/* Bolhas — outros */
.both {
    background: #1f2c34;
    color: #e9edef;
    border-radius: 7.5px 7.5px 7.5px 0;
    padding: 6px 9px 22px 9px;
    margin: 2px 0;
    max-width: 67%;
    float: left;
    clear: both;
    word-wrap: break-word;
    line-height: 1.5;
    position: relative;
    box-shadow: 0 1px 2px rgba(0,0,0,.4);
}

/* Nickname dentro da bolha */
.bnick {
    font-size: 12.5px;
    font-weight: 700;
    margin-bottom: 2px;
}

/* Rodapé da bolha: hora + tick (canto inferior direito) */
.bfoot {
    position: absolute;
    bottom: 4px;
    right: 8px;
    font-size: 10.5px;
    color: rgba(233,237,239,0.55);
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 3px;
}
.tick-ok  { color: #53bdeb; }
.tick-bad { color: #f56a6a; }

/* Separador de data */
.date-sep {
    text-align: center;
    margin: 10px 0 6px;
    clear: both;
    font-size: 11.5px;
    color: #8696a0;
}
.date-sep span {
    background: #182229;
    border-radius: 8px;
    padding: 3px 10px;
}

/* Carteira */
.wallet-box {
    font-family: monospace;
    font-size: 12px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px 12px;
    color: #58a6ff;
    letter-spacing: 1px;
    word-break: break-all;
}

/* Badge da sala */
.room-badge {
    font-family: monospace;
    font-size: 12px;
    color: #888;
    background: #111;
    border: 1px solid #222;
    border-radius: 6px;
    padding: 3px 10px;
}

/* Entrada */
.entry-card { max-width: 440px; margin: 40px auto; }
</style>
""", unsafe_allow_html=True)


# ─── Cores por carteira (estilo WhatsApp grupo) ────────────────────────────────
_CORES_NICK = ["#53bdeb", "#ec7228", "#bf59cf", "#06cf9c", "#f0a732", "#f56a6a", "#3fc4a0"]

def cor_nick(wallet: str) -> str:
    idx = int(hashlib.md5(wallet.encode()).hexdigest(), 16) % len(_CORES_NICK)
    return _CORES_NICK[idx]


# ─── Session state ─────────────────────────────────────────────────────────────
if "private_key" not in st.session_state:
    priv, pub = gerar_par_chaves()
    st.session_state.private_key = priv
    st.session_state.public_key  = pub
    st.session_state.wallet      = calcular_wallet(pub)

for key, default in [("room_code", ""), ("nickname", ""), ("na_sala", False)]:
    if key not in st.session_state:
        st.session_state[key] = default

params   = st.query_params
room_url = params.get("room", "")


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 Chat Seguro")
    st.caption("Mensagens cifradas · Identidade pseudônima")
    st.divider()

    st.markdown("**Sua carteira**")
    st.markdown(
        f'<div class="wallet-box">🪪 {st.session_state.wallet}</div>',
        unsafe_allow_html=True,
    )
    if st.session_state.nickname:
        st.caption(f"Apelido: **{st.session_state.nickname}**")
    st.caption("Endereço anônimo — sem nome real")

    st.divider()
    st.markdown("**Identidade persistente**")

    st.download_button(
        "⬇️ Exportar chave (.pem)",
        data=st.session_state.private_key,
        file_name="minha_identidade_chat.pem",
        mime="application/x-pem-file",
        help="Salve para manter o mesmo endereço na próxima sessão",
        use_container_width=True,
    )

    arq = st.file_uploader(
        "⬆️ Importar chave (.pem)",
        type=["pem"],
        key="upload_key",
        help="Carregue sua chave salva anteriormente",
    )
    if arq is not None:
        resultado = validar_chave_privada(arq.read())
        if resultado:
            st.session_state.private_key, st.session_state.public_key = resultado
            st.session_state.wallet  = calcular_wallet(st.session_state.public_key)
            st.session_state.na_sala = False
            st.success("Identidade carregada!")
            st.rerun()
        else:
            st.error("Arquivo inválido.")

    st.divider()
    st.caption("🔒 AES-256-GCM · RSA-2048-PSS\nSem servidor central.")


# ─── Main ─────────────────────────────────────────────────────────────────────
st.markdown("## 💬 Chat Seguro")

if not st.session_state.na_sala:
    # ── Tela de entrada ────────────────────────────────────────────────────────
    st.markdown('<div class="entry-card">', unsafe_allow_html=True)
    st.markdown("### Entrar na sala")

    nick = st.text_input(
        "Seu apelido",
        value=st.session_state.nickname,
        placeholder="Ex: Carlos, Ana, Dev01…",
        max_chars=32,
    )
    room_default = room_url or st.session_state.room_code
    codigo = st.text_input(
        "Código da sala",
        value=room_default,
        type="password",
        placeholder="Código combinado com sua equipe (mín. 8 chars)",
    )
    entrar = st.button("Entrar →", type="primary", use_container_width=True)

    if entrar:
        if not nick.strip():
            st.error("Escolha um apelido.")
        elif len(codigo.strip()) < 8:
            st.error("O código deve ter pelo menos 8 caracteres.")
        else:
            st.session_state.nickname  = nick.strip()
            st.session_state.room_code = codigo.strip()
            st.session_state.na_sala   = True
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    with st.expander("ℹ️ Como funciona"):
        st.markdown("""
- **Apelido e mensagens** são cifrados — só quem tem o código da sala lê
- Identidade = hash anônimo da chave pública (sem nome real)
- Blockchain local: hash encadeado + assinatura garantem integridade
- Compartilhe o código de sala por WhatsApp ou pessoalmente
        """)

else:
    # ── Chat ativo ─────────────────────────────────────────────────────────────
    room       = st.session_state.room_code
    meu_wallet = st.session_state.wallet
    meu_nick   = st.session_state.nickname

    # Cabeçalho
    col_titulo, col_share, col_sair = st.columns([4, 2, 1])
    with col_titulo:
        sala_mask = "*" * max(4, len(room) - 4) + room[-4:]
        st.markdown(
            f'Sala: <span class="room-badge">{sala_mask}</span>',
            unsafe_allow_html=True,
        )
    with col_share:
        st.markdown(
            f'<a href="?room={html.escape(room)}" target="_blank" '
            f'style="font-size:12px;color:#555;">🔗 Link da sala</a>',
            unsafe_allow_html=True,
        )
    with col_sair:
        if st.button("Sair", use_container_width=True):
            st.session_state.na_sala   = False
            st.session_state.room_code = ""
            st.rerun()

    stats = info_sala(room)
    st.caption(f"⛓️ {stats['altura']} blocos · {stats['mensagens']} mensagens")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Mensagens ──────────────────────────────────────────────────────────────
    mensagens  = ler_mensagens(room)
    data_atual = None

    partes = [
        '<div class="chat-wrapper">',
        '  <div class="chat-bg"><span class="chat-bg-text">GAT VI</span></div>',
        '  <div class="chat-scroll" id="chatscroll">',
    ]

    if not mensagens:
        partes.append(
            '<p style="color:#3a4a55;text-align:center;margin-top:200px;font-size:14px;">'
            '🔒 Sala vazia — envie a primeira mensagem</p>'
        )
    else:
        for m in mensagens:
            eh_meu = m["sender"] == meu_wallet
            dt     = datetime.fromtimestamp(m["timestamp"])
            data_d = dt.strftime("%d/%m/%Y")
            hora   = dt.strftime("%H:%M")

            # Separador de data
            if data_d != data_atual:
                data_atual = data_d
                partes.append(f'<div class="date-sep"><span>{data_d}</span></div>')

            txt_safe = html.escape(m["texto"])
            tick     = '<span class="tick-ok">✓✓</span>' if m["valido"] else '<span class="tick-bad">✗</span>'

            if eh_meu:
                partes.append(
                    f'<div class="bown">'
                    f'{txt_safe}'
                    f'<div class="bfoot">{hora} {tick}</div>'
                    f'</div>'
                )
            else:
                nome   = html.escape(m["nickname"]) if m["nickname"] else (m["sender"][:8] + "…")
                cor    = cor_nick(m["sender"])
                partes.append(
                    f'<div class="both">'
                    f'<div class="bnick" style="color:{cor};">{nome}</div>'
                    f'{txt_safe}'
                    f'<div class="bfoot">{hora}</div>'
                    f'</div>'
                )

    partes.append('  </div>')  # fecha chat-scroll
    partes.append('</div>')    # fecha chat-wrapper

    # Scroll para o fim (com pequeno delay para garantir render)
    partes.append("""
<script>
(function scroll(){
    var el = document.getElementById('chatscroll');
    if(!el){ setTimeout(scroll, 80); return; }
    el.scrollTop = el.scrollHeight;
})();
</script>""")

    st.markdown("".join(partes), unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Enviar (Enter ou botão) ────────────────────────────────────────────────
    col_upd, col_auto = st.columns([1, 3])
    with col_upd:
        if st.button("🔄 Atualizar", use_container_width=True):
            st.rerun()
    with col_auto:
        auto = st.checkbox("Auto-atualizar (5s)")

    with st.form(key="msg_form", clear_on_submit=True):
        col_msg, col_btn = st.columns([8, 1])
        with col_msg:
            texto = st.text_input(
                "msg",
                placeholder="Digite sua mensagem e pressione Enter…",
                label_visibility="collapsed",
            )
        with col_btn:
            enviar = st.form_submit_button("Enviar", type="primary", use_container_width=True)

    if enviar and texto.strip():
        try:
            enviar_mensagem(
                room_code=room,
                private_pem=st.session_state.private_key,
                public_pem=st.session_state.public_key,
                wallet=meu_wallet,
                texto=texto.strip(),
                nickname=meu_nick,
            )
        except Exception as e:
            st.error(f"Erro ao enviar: {e}")
        st.rerun()

    if auto:
        time.sleep(5)
        st.rerun()
