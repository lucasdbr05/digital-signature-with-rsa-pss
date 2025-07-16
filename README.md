# Digital Signature com RSA-PSS

Este projeto implementa um sistema de assinatura digital com padding customizado utilizando RSA com o padrão de assinatura PSS.

### Integrantes:

<table>
  <tr>
    <td align="center"><a href="https://github.com/pedro-neris" target="_blank"><img style="border-radius: 50%;" src="https://github.com/pedro-neris.png" width="100px;" alt="Pedro Neris"/><br /><sub><b>Pedro Neris - 231018964</b></sub></a><br /></td>
    <td align="center"><a href="https://github.com/lucasdbr05" target="_blank"><img style="border-radius: 50%;" src="https://github.com/lucasdbr05.png" width="100px;" alt="Lucas Lima"/><br /><sub><b>Lucas Lima - 231003406</b></sub></a><br /></td>
    <td align="center"><a href="https://github.com/rafaelghiorzi" target="_blank"><img style="border-radius: 50%;" src="https://github.com/rafaelghiorzi.png" width="100px;" alt="Rafael Dias"/><br /><sub><b>Rafael Dias - 232006144</b></sub></a><br /></td>
</table>


## Como rodar

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Execute a interface web:
   ```bash
   streamlit run main.py
   ```

## Funcionalidades da interface (main.py)

- **Assinar Mensagem ou Arquivo**
  - Escolha entre assinar um texto digitado ou um arquivo.
  - Clique em "Assinar Mensagem" ou "Assinar Arquivo" para gerar a assinatura digital.
  - A assinatura e o salt são exibidos em base64, com botões para fácil cópia.

- **Verificar Assinatura Digital**
  - Escolha entre verificar um texto ou um arquivo.
  - Informe a assinatura (base64) e o salt (base64) gerados anteriormente.
  - Clique em "Verificar Assinatura" para validar a assinatura.
  - O resultado da verificação é mostrado na tela (válida ou inválida).

## Como funciona o RSA neste projeto
- Geração automática de chaves RSA (p, q, n, e, d) na primeira execução.
- As chaves são salvas em arquivos `.pem` na pasta `keys/`.
- O módulo `RSA.py` implementa:
  - Geração de primos grandes (p, q) usando Miller-Rabin.
  - Cálculo de n = p * q, phi(n), e (expoente público) e d (expoente privado).
  - Criptografia (encrypt) e decriptografia (decrypt) usando exponenciação modular.
  - Salvamento e leitura das chaves em formato PEM.

## Como funciona o PSS neste projeto
- O módulo `RSA_PSS.py` implementa um padding customizado inspirado no padrão PSS:
  - Para assinar:
    1. Calcula o hash da mensagem.
    2. Gera um salt aleatório.
    3. Gera uma string de preenchimento (PS) usando MGF1 (Mask Generation Function).
    4. Monta o bloco EM: `0x00 || 0x01 || PS || 0x00 || H(M) || SALT`.
    5. Converte EM para inteiro e assina usando a chave privada RSA.
    6. Retorna a assinatura e o salt em base64.
  - Para verificar:
    1. Decodifica assinatura e salt de base64.
    2. Recupera EM usando a chave pública RSA.
    3. Extrai e valida o padding, hash e salt do bloco EM.
    4. Compara o hash e o salt com os valores esperados.
    5. Retorna se a assinatura é válida ou não.
