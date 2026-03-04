# 🛡️ Forensic Analyzer — SOC File & Boleto Tool

Ferramenta de análise forense de arquivos e validação de boletos bancários, desenvolvida para uso em contexto de SOC (Security Operations Center) e estudos de cybersecurity.

> **Desenvolvido por:** João Carlos Minozzi  
> **Contexto:** SOC / Cybersecurity enthusiast — uso educacional

---

## ⚡ Funcionalidades

### Análise de Arquivos
- **Hashes**: MD5, SHA-1, SHA-256, SHA-512 (calculados localmente)
- **Magic bytes**: detecção do tipo real do arquivo (bypassa extensão falsificada)
- **Spoofing de extensão**: detecta quando .doc é na verdade um PE, etc.
- **Entropia de Shannon**: identifica conteúdo cifrado/empacotado/ofuscado
- **Hex dump**: primeiros 128 bytes em formato hexadecimal
- **Timestamps**: data de criação, modificação e acesso do arquivo no sistema

### Análise por Tipo
| Tipo | Análise |
|------|---------|
| **EXE / DLL** | Cabeçalho PE: arquitetura, timestamp de compilação, ASLR, DEP/NX, CFG, seções suspeitas (UPX, Themida, VMProtect), seções W+X |
| **PDF** | Versão, metadados completos (Creator, Producer, datas), JavaScript embutido, /OpenAction, /EmbeddedFile, strings suspeitas, URLs, formulários, detector de boletos |
| **ZIP / DOCX / XLSX** | Listagem de arquivos internos, flag de executáveis e documentos com macros |
| **Qualquer** | Extração de strings ASCII: IPs, URLs, emails, IOCs genéricos |

### Validação de Boletos (FEBRABAN)
| Formato | Suporte |
|---------|---------|
| Linha digitável bancária | 47 dígitos |
| Código de barras bancário | 44 dígitos |
| Arrecadação / concessionária | 48 dígitos (início em 8) |

- Validação por **módulo 10** e **módulo 11 FEBRABAN** campo a campo
- Decode do **campo livre** por banco (BB, Bradesco, Itaú, CEF, Santander, Sicredi, Sicoob...)
- Reconstrução do **código de barras** a partir da linha digitável
- Decodificação do **fator de vencimento** → data real
- Identificação de **400+ bancos** pela base ISPB
- Alerta de **boleto vencido**

### VirusTotal
- Consulta o hash SHA-256 na API do VirusTotal (o arquivo **nunca é enviado**)
- Timeout de 10 segundos
- Tratamento de rate limit, chave inválida, arquivo não encontrado

---

## 🚀 Instalação

```bash
git clone https://github.com/seu-usuario/forensic-analyzer.git
cd forensic-analyzer
pip install -r requirements.txt
```

**Dependências:**
- Python 3.10+
- `colorama` — cores no terminal
- `requests` — consulta ao VirusTotal
- `pdfplumber` — extração de texto de PDFs
- `python-dotenv` — carregamento do `.env`

---

## ⚙️ Configuração (.env)

Crie seu arquivo de configuração a partir do template:

```bash
cp .env.example .env
```

Edite o `.env` com suas credenciais:

```env
VT_API_KEY=sua_chave_do_virustotal_aqui
VT_TIMEOUT=10
AUTO_SAVE_JSON=false
```

> O arquivo `.env` já está no `.gitignore` e **nunca será commitado**.  
> A chave do VirusTotal é gratuita em [virustotal.com](https://www.virustotal.com).

**Prioridade de configuração:**
1. `--vt-key` passado direto na CLI
2. Variável de ambiente do sistema (`export VT_API_KEY=...`)
3. Arquivo `.env` na raiz do projeto



## 📖 Uso

```bash
# Analisar um arquivo
python analyzer.py arquivo.pdf

# Com VirusTotal
python analyzer.py arquivo.exe --vt-key SUA_CHAVE_AQUI

# Validar boleto manualmente
python analyzer.py --boleto "34191.09008 61207.727308 71444.640003 8 92690000010000"

# Analisar PDF com boleto + VT + salvar relatório JSON
python analyzer.py boleto.pdf --vt-key SUA_CHAVE --json relatorio.json

# Análise rápida (sem extração de strings)
python analyzer.py arquivo_grande.zip --no-strings

# Apenas hashes e hex dump
python analyzer.py arquivo.bin --hex-only
```

---

## 📊 Exemplo de Output

```
═════════════════════════════════════════════════════════════════
  FORENSIC ANALYZER v2.0.0  //  SOC Toolkit
═════════════════════════════════════════════════════════════════

  ► Carregando arquivo: documento.pdf
  ► Calculando hashes (MD5 / SHA-1 / SHA-256 / SHA-512)...
  ► Identificando tipo pelo magic bytes...
  ► Analisando PDF (metadados + estrutura)...
  ► Consultando VirusTotal (hash SHA-256)...
  ► Gerando findings e score de risco...

──────────────── RESULTADO — documento.pdf ────────────────

  🚨  ALTO RISCO — não abrir/executar
     3 indicador(es) · 1.43s
     [████████████████░░░░░░░░░░░░░░░░░░░░░░░░] 55/100

┌─ INDICADORES / FINDINGS ────────────────────────────────────┐
  [CRIT] JavaScript embutido: 2 ocorrência(s) — PDFs com JS podem
         executar código arbitrário ao abrir...
  [HIGH] Gerador suspeito: 'FPDF 1.7' — ferramenta genérica
         frequentemente usada em geração de documentos falsos.
  [MED]  Metadados ausentes (Creator, Author e Title não definidos)
└──────────────────────────────────────────────────────────────┘
```

---

## 🔒 Privacidade

- **Nenhum arquivo é enviado a servidores externos**
- Somente o hash SHA-256 é consultado no VirusTotal (apenas se a chave for fornecida)
- Toda análise de conteúdo é feita localmente

---

## ⚠️ Aviso Legal

Esta ferramenta é para uso **educacional e profissional em contexto de SOC**.  
Resultados são indicativos — não substituem análise forense profissional.

Para boletos: a validação dos dígitos verificadores **NÃO garante autenticidade**.  
Boletos clonados podem ter DVs corretos com conta beneficiária diferente.  
**Sempre confirme o CNPJ/CPF e nome do beneficiário no internet banking antes de pagar.**

---

## 📁 Estrutura do Projeto

```
forensic-analyzer/
├── analyzer.py              # CLI principal
├── config.py                # Carrega .env e expõe configurações
├── requirements.txt
├── .env.example             # Template público — copie para .env
├── .env                     # Suas credenciais (no .gitignore)
├── .gitignore
├── README.md
└── modules/
    ├── __init__.py
    ├── output.py            # Helpers de terminal (colorama)
    ├── file_info.py         # Hashes, magic bytes, entropia, timestamps
    ├── pe_parser.py         # Análise de cabeçalho PE (sem dependências externas)
    ├── pdf_parser.py        # Análise de PDF (pdfplumber + raw bytes)
    ├── zip_strings.py       # ZIP listing + extração de strings/IPs/URLs
    ├── boleto.py            # Validação completa de boletos FEBRABAN
    ├── findings.py          # Engine de findings e score de risco
    └── virustotal.py        # API VirusTotal com timeout
```

---

## 🤝 Contribuindo

Issues e PRs são bem-vindos. Áreas de melhoria:
- Suporte a RAR/7z internos
- Análise de scripts (VBS, PS1, JS)
- Integração com outras threat intel APIs (AbuseIPDB, URLScan.io)
- Output em HTML
