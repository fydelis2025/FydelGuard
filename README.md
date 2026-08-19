# 🛡️ FydelGuard

> **Antivírus Profissional e Proteção Avançada para Linux** desenvolvido por **FydelisTech**.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![Qt5](https://img.shields.io/badge/Qt-5.15%2B-green.svg)](https://www.qt.io/)
[![ClamAV](https://img.shields.io/badge/ClamAV-1.4%2B-orange.svg)](https://www.clamav.net/)

O **FydelGuard** é uma solução de segurança moderna e completa voltada para ambientes Linux e automação comercial. Ele combina a robustez do motor antivírus **ClamAV**, monitoramento de sistema em tempo real via **fanotify**, gerenciamento seguro de quarentena com **SQLite** e controle integrado do **UFW (Firewall)**, tudo em uma interface gráfica (GUI) elegante construída em Qt com temas escuros e design neon.

---

## ✨ Recursos Principais

* **🔍 Varredura Multithread:** Escaneamento rápido e eficiente de arquivos e diretórios utilizando filas concorrentes e múltiplas threads.
* **⚡ Proteção em Tempo Real:** Monitoramento contínuo de atividades do sistema utilizando eventos do kernel (`fanotify`).
* **📦 Gerenciador de Quarentena:** Isolamento seguro de arquivos maliciosos gerenciado por um banco de dados SQLite local.
* **🔥 Firewall Integrado:** Visualização, ativação e gerenciamento simplificado de regras do UFW direto pela interface.
* **🔄 Atualizador de Assinaturas:** Integração com o `freshclam` para manter a base de ameaças sempre atualizada.
* **🎨 Interface Moderna:** Dashboard responsivo desenvolvido em Qt com paleta de cores personalizada e indicadores visuais de estado.

---

## 🛠️ Tecnologias Utilizadas

* **Linguagem:** C++17
* **Interface Gráfica:** Qt5 / Qt Widgets
* **Antivírus Engine:** LibClamAV
* **Banco de Dados (Quarentena):** SQLite3
* **Build System:** CMake

---

## 🚀 Instalação Rápida

A forma mais fácil de compilar e gerar o pacote de instalação `.deb` na sua distribuição Linux baseada em Debian/Ubuntu é utilizando o script automatizado `install.sh`:

```bash
# Clone o repositório
git clone [https://github.com/SEU_USUARIO/fydelguard.git](https://github.com/SEU_USUARIO/fydelguard.git)
cd fydelguard

# Dê permissão de execução ao script de instalação
chmod +x install.sh

# Execute o script (ele verificará dependências, compilará e gerará o .deb)
sudo ./install.sh
