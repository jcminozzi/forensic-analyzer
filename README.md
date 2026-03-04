# 🛡️ Forensic Analyzer — SOC File & Boleto Tool

Ferramenta de análise forense de arquivos, emails e boletos bancários desenvolvida para uso em SOC (Security Operations Center) e estudos de cybersecurity.

> **Desenvolvido por:** João Carlos Minozzi  
> **Contexto:** SOC / Cybersecurity enthusiast — uso educacional

---

## ⚡ Funcionalidades

### Análise de Arquivos
- **Hashes**: MD5, SHA-1, SHA-256, SHA-512 (calculados localmente)
- **Magic bytes**: detecção do tipo real — bypassa extensão falsificada
- **Spoofing de extensão**: detecta quando `.doc` é na verdade um PE, etc.
- **Entropia de Shannon**: identifica conteúdo cifrado, empacotado ou ofuscado
- **Hex dump**: primeiros 128 bytes em formato hexadecimal
- **Timestamps**: data de criação, modificação e acesso do arquivo no sistema
- **Extração de strings**: IPs, URLs, emails e IOCs direto dos bytes brutos

### Análise por Tipo
| Tipo | O que é analisado |
|------|-------------------|
| **EXE / DLL** | Cabeçalho PE: arquitetura, timestamp de compilação, ASLR, DEP/NX, CFG, seções suspeitas (UPX, Themida, VMProtect), seções W+X |
| **PDF** | Versão, metadados completos, JavaScript embutido, /OpenAction, /EmbeddedFile, strings suspeitas, URLs, detector automático de boleto |
| **ZIP / DOCX / XLSX** | Listagem interna, flag de executáveis e documentos com macros |
| **EML** | Spoofing, SPF/DKIM/DMARC, cadeia de Received, display name fraud, homógrafos, anexos perigosos |
| **Qualquer binário** | Hashes, entropia, magic bytes, strings, IPs, URLs |

### Análise de Email (.eml)
- **SPF / DKIM / DMARC** lidos do header `Authentication-Results`
- **From vs Reply-To / Return-Path**: detecta domínio divergente
- **Display name spoofing**: "Banco Bradesco" enviando de `bradesc0.com`
- **Ataque homógrafo**: caracteres Unicode disfarçados no domínio remetente
- **Provedores temporários/descartáveis**: mailinator, guerrillamail, etc.
- **Cadeia de Received**: todos os hops com IPs e timestamps
- **Anexos perigosos**: `.exe`, `.docm`, `.lnk`, `.iso`, `.ps1`, etc.
- **URLs com IP direto** e encurtadores suspeitos no corpo

### Varredura de Pasta
- Recursiva ou só na raiz, com ou sem filtro de extensões
- Ignora automaticamente pastas de sistema/desenvolvimento
- Score de risco por arquivo em tempo real
- Sumário final com destaque dos mais suspeitos
- Exportação de relatório JSON da varredura completa

### Validação de Boletos (FEBRABAN)
| Formato | Dígitos |
|---------|---------|
| Linha digitável bancária | 47 |
| Código de barras bancário | 44 |
| Arrecadação / concessionária | 48 (início em 8) |

- Módulo 10 e 11 FEBRABAN campo a campo
- Decode do campo livre por banco (BB, Bradesco, Itaú, CEF, Santander...)
- Fator de vencimento → data real com alerta de vencido

### VirusTotal
- Consulta hash SHA-256 — o arquivo **nunca é enviado**
- Timeout configurável, tratamento de rate limit e chave inválida

---

## 🚀 Instalação

```bash
git clone https://github.com/seu-usuario/forensic-analyzer.git
cd forensic-analyzer
pip install -r requirements.txt
cp .env.example .env   # configure sua chave VT aqui
```

**Dependências:** Python 3.10+, `colorama`, `requests`, `pdfplumber`, `python-dotenv`

---

## ⚙️ Configuração (.env)

```env
VT_API_KEY=sua_chave_do_virustotal_aqui
VT_TIMEOUT=10
AUTO_SAVE_JSON=false
# OUTPUT_DIR=./relatorios
```

> O `.env` está no `.gitignore` e nunca será commitado.  
> Chave gratuita em [virustotal.com](https://www.virustotal.com) → Join us → API Key.

**Prioridade:** `--vt-key` na CLI > variável de ambiente do sistema > arquivo `.env`

---

## 📖 Uso

### Modo Interativo (recomendado)

```bash
python analyzer.py        # abre o menu automaticamente
python analyzer.py -i     # equivalente
```

```
[1] Analisar Arquivo        PDF, EXE, DLL, ZIP, DOCX, EML...
[2] Analisar Pasta          Varre arquivos recursivamente
[3] Analisar Email (.eml)   Spoofing, SPF/DKIM/DMARC, Received chain
[4] Validar Boleto          Linha digitável ou código de barras FEBRABAN
[5] Configurações           Chave VT, status do .env
[0] Sair
```

### Modo Direto (CLI)

```bash
python analyzer.py arquivo.pdf
python analyzer.py email.eml
python analyzer.py malware.exe --vt-key SUA_CHAVE
python analyzer.py --boleto "34191.09008 61207.727308 71444.640003 8 92690000010000"
python analyzer.py arquivo.pdf --json relatorio.json
python analyzer.py arquivo_grande.zip --no-strings
```

---

## 📂 De onde o analisador lê arquivos?

A ferramenta lê **qualquer arquivo ou pasta que seu usuário tenha permissão de leitura**. Basta informar o caminho — absoluto, relativo ou com `~`.

### Exemplos de caminhos aceitos

| Sistema | Exemplo |
|---------|---------|
| **Windows** | `C:\Users\joao\Downloads\boleto.pdf` |
| **Windows** | `C:\Users\joao\Desktop\suspeito.exe` |
| **Windows** | `.\amostras\malware.bin` *(relativo ao diretório atual)* |
| **Linux** | `/home/joao/downloads/arquivo.pdf` |
| **Linux** | `/tmp/suspeito.exe` |
| **Linux/Mac** | `~/Downloads/email.eml` |
| **macOS** | `/Users/joao/Downloads/boleto.pdf` |
| **Rede** | `\\servidor\share\arquivo.pdf` *(se acessível)* |

> **Dica Windows:** Arraste o arquivo direto no terminal para colar o caminho completo automaticamente.

### Permissões necessárias

| Local | Precisa de admin/sudo? |
|-------|----------------------|
| Pasta pessoal, Downloads, Desktop, Documentos | ❌ Não |
| `/tmp` (Linux) ou `%TEMP%` (Windows) | ❌ Não |
| Arquivos de rede mapeados | ❌ Não (se tiver acesso) |
| `C:\Windows\System32` | ✅ Sim (Windows Admin) |
| `/etc`, `/sys`, `/proc` | ✅ Sim (sudo Linux) |

### Pastas ignoradas na varredura

Para não analisar arquivos de sistema ou de desenvolvimento, as seguintes pastas são **sempre puladas automaticamente**:

```
__pycache__    .git         .svn          .hg
node_modules   .venv        venv          env
dist           build        Windows       System32
SysWOW64       Program Files             Program Files (x86)
```

Pastas ocultas (início com `.`) também são ignoradas por padrão.

### Extensões analisadas em profundidade (filtro de varredura)

Ao ativar o filtro de extensões na varredura de pasta, apenas estes tipos são processados:

| Categoria | Extensões |
|-----------|-----------|
| **Executáveis** | `.exe` `.dll` `.sys` `.scr` `.bat` `.cmd` `.ps1` `.vbs` `.js` `.hta` `.wsf` `.pif` `.com` `.msi` `.reg` |
| **Documentos** | `.pdf` `.doc` `.docx` `.docm` `.xls` `.xlsx` `.xlsm` `.ppt` `.pptx` `.pptm` `.rtf` |
| **Compactados** | `.zip` `.rar` `.7z` `.gz` `.tar` |
| **Email** | `.eml` `.msg` |
| **Outros** | `.jar` `.apk` `.iso` `.img` `.lnk` |

Sem o filtro, **todos os arquivos** da pasta são analisados (hashes, entropia, magic bytes).

### Limite de tamanho

Por padrão, durante a varredura de pasta, arquivos acima de **200 MB** são pulados (configurável no menu). Para arquivos únicos via CLI não há limite — mas arquivos muito grandes naturalmente demoram mais no cálculo de hash e extração de strings.

---

## 🔒 Privacidade

- **Nenhum arquivo é enviado a servidores externos**
- Somente o hash SHA-256 é consultado no VirusTotal (e só se a chave estiver configurada)
- Toda análise de conteúdo é 100% local

---

## ⚠️ Aviso Legal

Uso **educacional e profissional em contexto de SOC**. Resultados são indicativos.

Para boletos: DVs corretos **não garantem autenticidade** — boletos clonados podem ter DVs válidos com conta beneficiária trocada. Sempre confirme CNPJ/CPF e nome do beneficiário no internet banking antes de pagar.

---

## 📁 Estrutura do Projeto

```
forensic-analyzer/
├── analyzer.py              # CLI principal (entry point)
├── interactive.py           # Menu interativo TUI
├── config.py                # Carrega .env e expõe configurações
├── requirements.txt
├── .env.example             # Template público — copie para .env
├── .env                     # Suas credenciais (no .gitignore)
├── .gitignore
├── README.md
└── modules/
    ├── __init__.py
    ├── output.py            # Helpers de terminal colorido (colorama)
    ├── file_info.py         # Hashes, magic bytes, entropia, timestamps
    ├── pe_parser.py         # Análise de cabeçalho PE (sem pefile)
    ├── pdf_parser.py        # Análise de PDF (pdfplumber + raw bytes)
    ├── eml_parser.py        # Análise de email: spoofing, SPF/DKIM/DMARC
    ├── zip_strings.py       # ZIP listing + extração de strings/IPs/URLs
    ├── boleto.py            # Validação FEBRABAN (bancário + arrecadação)
    ├── findings.py          # Engine de findings e score de risco
    └── virustotal.py        # API VirusTotal com timeout configurável
```

---

## 🤝 Contribuindo

Issues e PRs são bem-vindos. Ideias:
- Suporte a RAR/7z (listagem interna)
- Análise estática de scripts VBS, PS1, JS
- Integração com AbuseIPDB e URLScan.io
- Modo watch: monitorar pasta em tempo real
- Output em HTML
