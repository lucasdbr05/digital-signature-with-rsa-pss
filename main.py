import streamlit as st
from RSA_PSS import RSAPSS
import base64
from pprint import pprint 
import hashlib

st.title("Assinatura Digital RSA-PSS")

@st.cache_resource
def get_pss():
    return RSAPSS()

pss = get_pss()

st.header("Assinar Mensagem ou Arquivo")
assinatura = None
salt = None

tipo = st.radio("Tipo de entrada", ("Texto", "Arquivo"))

if tipo == "Texto":
    mensagem = st.text_area("Mensagem para assinar")
    assinatura = st.session_state.get("assinatura_text", "")
    salt = st.session_state.get("salt_text", "")
    if st.button("Assinar Mensagem"):
        if mensagem:
            assinatura, salt = pss.sign(mensagem.encode())
            priv_key = pss.rsa.load_pem_key(pss.rsa.key_paths["inv_e"])
            message_hash = hashlib.new(pss.hash_alg, mensagem.encode()).hexdigest()
            dict_assinatura = {
                "private_key": str(priv_key),
                "hash": message_hash,
                "salt": salt
            }
            st.session_state["assinatura_text"] = assinatura
            st.session_state["salt_text"] = salt
            st.success("Mensagem assinada!")
            st.write("Dicionário da assinatura:")
            pprint(dict_assinatura)
        else:
            st.warning("Digite uma mensagem para assinar.")
    if assinatura:
        st.code(assinatura, language="text")
        st.text_input("Assinatura pronta para copiar", value=assinatura, key="assinatura_text_input")
    if salt:
        st.code(salt, language="text")
        st.text_input("Salt pronto para copiar", value=salt, key="salt_text_input")
else:
    arquivo = st.file_uploader("Selecione um arquivo para assinar", type=None)
    assinatura = st.session_state.get("assinatura_file", "")
    salt = st.session_state.get("salt_file", "")
    if arquivo and st.button("Assinar Arquivo"):
        conteudo = arquivo.read()
        assinatura, salt = pss.sign(conteudo)
        priv_key = pss.rsa.load_pem_key(pss.rsa.key_paths["inv_e"])
        message_hash = hashlib.new(pss.hash_alg, conteudo).hexdigest()
        dict_assinatura = {
            "private_key": str(priv_key),
            "hash": message_hash,
            "salt": salt
        }
        st.session_state["assinatura_file"] = assinatura
        st.session_state["salt_file"] = salt
        st.success("Arquivo assinado!")
        st.write("Dicionário da assinatura:")
        pprint(dict_assinatura)
    if assinatura:
        st.code(assinatura, language="text")
    if salt:
        st.code(salt, language="text")
        
        
st.header("Verificar Assinatura Digital")
ver_tipo = st.radio("Tipo de entrada para verificação", ("Texto", "Arquivo"), key="ver_tipo")

if ver_tipo == "Texto":
    mensagem_ver = st.text_area("Mensagem para verificar", key="msg_ver")
else:
    arquivo_ver = st.file_uploader("Selecione o arquivo para verificar", type=None, key="arq_ver")
    mensagem_ver = None
    if arquivo_ver:
        mensagem_ver = arquivo_ver.read()

assinatura_ver = st.text_input("Assinatura (base64)")
salt_ver = st.text_input("Salt (base64)")

if st.button("Verificar Assinatura"):
    if (ver_tipo == "Texto" and mensagem_ver) or (ver_tipo == "Arquivo" and mensagem_ver):
        if assinatura_ver and salt_ver:
            pub_key = pss.rsa.load_pem_key(pss.rsa.key_paths["e"])
            m_hash = hashlib.new(pss.hash_alg, mensagem_ver.encode() if ver_tipo == "Texto" else mensagem_ver).hexdigest()
            dict_verificacao = {
                "public_key": str(pub_key),
                "hash": m_hash,
                "salt": salt_ver
            }
            valido = pss.verify(mensagem_ver.encode() if ver_tipo == "Texto" else mensagem_ver, assinatura_ver, salt_ver)
            st.write("Dicionário da verificação:")
            pprint(dict_verificacao)
            st.code(dict_verificacao, language="python")
            if valido:
                st.success("Assinatura válida!")
            else:
                st.error("Assinatura inválida!")
        else:
            st.warning("Preencha assinatura e salt.")
    else:
        st.warning("Forneça a mensagem ou arquivo para verificação.")
