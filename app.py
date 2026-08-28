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

.chat-box {
    background: #0e0e0e;
    border: 1px solid #222;
    border-radius: 14px;
    padding: 20px 16px;
    min-height: 440px;
    overflow-y: auto;
}

.bubble-own {
    background: #1a73e8;
    color: #fff;
    border-radius: 18px 18px 4px 18px;
    padding: 10px 15px;
    margin: 4px 0 2px;
    max-width: 68%;
    float: right;
    clear: both;
    word-wrap: break-word;
    line-height: 1.45;
}

.bubble-other {
    background: #1e1e1e;
    color: #ddd;
    border: 1px solid #2a2a2a;
    border-radius: 18px 18px 18px 4px;
    padding: 10px 15px;
    margin: 4px 0 2px;
    max-width: 68%;
    float: left;
    clear: both;
    word-wrap: break-word;
    line-height: 1.45;
}

.meta-own   { font-size: 11px; color: #666; text-align: right; clear: both; margin-bottom: 10px; padding-right: 4px; }
.meta-other { font-size: 11px; color: #666; text-align: left;  clear: both; margin-bottom: 10px; padding-left: 4px; }

.nick-label { font-weight: 600; color: #aaa; font-size: 12px; }
.sig-ok     { color: #4caf50; }
.sig-bad    { color: #f44336; }

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

.room-badge {
    font-family: monospace;
    font-size: 12px;
    color: #888;
    background: #111;
    border: 1px solid #222;
    border-radius: 6px;
    padding: 3px 10px;
}

.entry-card {
    max-width: 460px;
    margin: 40px auto;
}
</style>
""", unsafe_allow_html=True)


# ─── Session state ─────────────────────────────────────────────────────────────
if "private_key" not in st.session_state:
    priv, pub = gerar_par_chaves()
    st.session_state.private_key = priv
    st.session_state.public_key  = pub
    st.session_state.wallet      = calcular_wallet(pub)

for key, default in [("room_code", ""), ("nickname", ""), ("na_sala", False)]:
    if key not in st.session_state:
        st.session_state[key] = default

# Suporte a ?room= na URL para compartilhar sala via link
params = st.query_params
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
    st.caption("Endereço gerado a partir da sua chave — sem nome real")

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
    st.caption(
        "🔒 AES-256-GCM · RSA-2048 PSS\n\n"
        "Nickname cifrado — invisível sem o código de sala.\n"
        "Sem servidor central. Sem metadados de identidade."
    )


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
        help="Visível apenas para quem está na mesma sala (cifrado).",
    )

    room_default = room_url or st.session_state.room_code
    codigo = st.text_input(
        "Código da sala",
        value=room_default,
        type="password",
        placeholder="Código combinado com sua equipe",
        help="Mínimo 8 caracteres. É a chave de criptografia — compartilhe fora deste app.",
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

    st.markdown("---")
    with st.expander("ℹ️ Como funciona"):
        st.markdown("""
**O que é criptografado:**
- ✅ Texto da mensagem (AES-256-GCM)
- ✅ Seu apelido (também cifrado com a chave da sala)
- ✅ Somente quem tem o código da sala consegue ler qualquer coisa

**O que fica no blockchain:**
- Endereço de carteira (hash anônimo, sem nome real)
- Horário do bloco
- Dados cifrados (ilegíveis sem o código)
- Hash encadeado + assinatura (garante integridade)

**Compartilhar sala:**
- Envie o código de sala por WhatsApp, Signal, pessoalmente
- Ou compartilhe o link `?room=CODIGO` — quem abrir ainda precisa do código
        """)

else:
    # ── Chat ativo ─────────────────────────────────────────────────────────────
    room       = st.session_state.room_code
    meu_wallet = st.session_state.wallet
    meu_nick   = st.session_state.nickname

    col_titulo, col_share, col_sair = st.columns([4, 2, 1])
    with col_titulo:
        sala_mask = "*" * max(4, len(room) - 4) + room[-4:]
        st.markdown(
            f'Sala: <span class="room-badge">{sala_mask}</span>',
            unsafe_allow_html=True,
        )
    with col_share:
        share_url = f"?room={room}"
        st.markdown(
            f'<a href="{share_url}" target="_blank" style="font-size:12px;color:#555;">'
            f'🔗 Link da sala</a>',
            unsafe_allow_html=True,
        )
    with col_sair:
        if st.button("Sair", use_container_width=True):
            st.session_state.na_sala   = False
            st.session_state.room_code = ""
            st.rerun()

    stats = info_sala(room)
    st.caption(f"⛓️ Altura: **{stats['altura']}** · Mensagens: **{stats['mensagens']}**")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Mensagens ──────────────────────────────────────────────────────────────
    mensagens = ler_mensagens(room)

    partes = ['<div class="chat-box">']

    if not mensagens:
        partes.append(
            '<p style="color:#444;text-align:center;margin-top:160px;">'
            '🔒 Sala vazia.<br>Envie a primeira mensagem.</p>'
        )
    else:
        for m in mensagens:
            eh_meu    = m["sender"] == meu_wallet
            ts_fmt    = datetime.fromtimestamp(m["timestamp"]).strftime("%d/%m %H:%M")
            nome_exib = html.escape(m["nickname"]) if m["nickname"] else (m["sender"][:8] + "…")
            sig_html  = '<span class="sig-ok">✓</span>' if m["valido"] else '<span class="sig-bad">✗</span>'
            txt_safe  = html.escape(m["texto"])

            if eh_meu:
                partes.append(f'<div class="bubble-own">{txt_safe}</div>')
                partes.append(
                    f'<div class="meta-own">'
                    f'<span class="nick-label">{html.escape(meu_nick)}</span> · {ts_fmt} · {sig_html}'
                    f'</div>'
                )
            else:
                partes.append(f'<div class="bubble-other">{txt_safe}</div>')
                partes.append(
                    f'<div class="meta-other">'
                    f'<span class="nick-label">{nome_exib}</span> · {ts_fmt} · {sig_html}'
                    f'</div>'
                )

    partes.append('</div>')
    partes.append("""
<script>
(function(){
    var boxes = document.querySelectorAll('.chat-box');
    if(boxes.length){ var b=boxes[boxes.length-1]; b.scrollTop=b.scrollHeight; }
})();
</script>""")

    st.markdown("".join(partes), unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Enviar mensagem ────────────────────────────────────────────────────────
    col_msg, col_btn, col_upd = st.columns([6, 1, 1])

    with col_msg:
        texto = st.text_input(
            "msg",
            placeholder="Digite sua mensagem…",
            label_visibility="collapsed",
            key="msg_input",
        )
    with col_btn:
        enviar = st.button("Enviar", type="primary", use_container_width=True)
    with col_upd:
        if st.button("🔄", use_container_width=True, help="Atualizar"):
            st.rerun()

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

    # ── Auto-atualizar ─────────────────────────────────────────────────────────
    with st.expander("⚙️ Auto-atualizar"):
        auto = st.checkbox("Atualizar a cada 5 segundos")
        if auto:
            time.sleep(5)
            st.rerun()
