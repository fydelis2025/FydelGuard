#!/bin/bash
set -euo pipefail

APP_NAME="fydelguard"
APP_VERSION="1.0.0"
ARCH="amd64"
DEB_DIR="${APP_NAME}_${APP_VERSION}_${ARCH}"

echo "========================================="
echo "  📦 Preparando e Compilando o FydelGuard"
echo "========================================="

# 0. Verifica e instala todas as dependências de compilação e desenvolvimento Qt/ClamAV
echo "[0/5] 🔍 Verificando dependências de desenvolvimento..."
NEEDED_DEPS="build-essential cmake fakeroot libclamav-dev libsqlite3-dev qtbase5-dev libqt5svg5-dev"
MISSING_DEPS=""

for dep in ${NEEDED_DEPS}; do
    if ! dpkg -s "${dep}" &>/dev/null; then
        MISSING_DEPS="${MISSING_DEPS} ${dep}"
    fi
done

if [ -n "${MISSING_DEPS}" ]; then
    echo "⚙️ Instalando dependências de compilação ausentes:${MISSING_DEPS}..."
    sudo apt update
    sudo apt install -y ${MISSING_DEPS}
fi

# 1. Compila o projeto
echo "[1/5] 🔧 Compilando..."
rm -rf build
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..

# 2. Cria estrutura do .deb
echo "[2/5] 📁 Montando estrutura..."
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/local/bin"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${DEB_DIR}/etc/fydelguard"
mkdir -p "${DEB_DIR}/etc/logrotate.d"
mkdir -p "${DEB_DIR}/lib/systemd/system"
mkdir -p "${DEB_DIR}/var/lib/fydelguard/quarantine"
mkdir -p "${DEB_DIR}/var/log/fydelguard"

# 3. Copia arquivos
echo "[3/5] 📄 Copiando arquivos..."
cp build/fydelguard "${DEB_DIR}/usr/local/bin/"
chmod 755 "${DEB_DIR}/usr/local/bin/fydelguard"
strip "${DEB_DIR}/usr/local/bin/fydelguard" 2>/dev/null || true

# Atalho .desktop
cat > "${DEB_DIR}/usr/share/applications/fydelguard.desktop" << EOF
[Desktop Entry]
Name=FydelGuard
GenericName=Antivírus
Comment=FydelGuard - Antivírus Profissional para FydelisTech
Exec=/usr/local/bin/fydelguard
Icon=fydelguard
Terminal=false
Type=Application
Categories=Security;System;
Keywords=antivirus;security;fydelis;clamav;
StartupNotify=true
StartupWMClass=FydelGuard
EOF

# Ícone SVG Profissional Embutido
cat > "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/fydelguard.svg" << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#6366f1"/>
      <stop offset="100%" stop-color="#9333ea"/>
    </linearGradient>
    <linearGradient id="glowGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#22c55e"/>
      <stop offset="100%" stop-color="#10b981"/>
    </linearGradient>
  </defs>
  <rect x="8" y="8" width="112" height="112" rx="26" fill="#0b1120" stroke="#1e293b" stroke-width="4"/>
  <path d="M64 20 L98 32 V58 C98 82 81 100 64 108 C47 100 30 82 30 58 V32 Z" fill="url(#shieldGrad)" stroke="#a855f7" stroke-width="2"/>
  <path d="M48 62 L58 72 L80 48" fill="none" stroke="url(#glowGrad)" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
SVGEOF

# Configuração padrão
cat > "${DEB_DIR}/etc/fydelguard/fydelguard.conf" << 'CONFEOF'
[geral]
modo=grafico
idioma=pt_BR
iniciar_minimizado=false

[scanner]
clamav_db_path=/var/lib/clamav
threads=4
scan_compress=true

[monitoramento]
tempo_real=true
fanotify_mount=/
bloquear_acesso=true

[quarentena]
diretorio=/var/lib/fydelguard/quarantine
dias_para_auto_remover=30

[firewall]
gerenciar_ufw=true
auto_ativar=false

[atualizacao]
auto_update=true
intervalo_horas=24

[log]
nivel=info
arquivo=/var/log/fydelguard/fydelguard.log
tamanho_max_mb=10
CONFEOF

# Logrotate
cat > "${DEB_DIR}/etc/logrotate.d/fydelguard" << 'LOGEOF'
/var/log/fydelguard/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LOGEOF

# Serviço systemd
cat > "${DEB_DIR}/lib/systemd/system/fydelguard.service" << 'SERVICEEOF'
[Unit]
Description=FydelGuard - Antivírus em Tempo Real
After=network.target clamav-daemon.service clamav-freshclam.service
Wants=clamav-daemon.service clamav-freshclam.service

[Service]
Type=simple
ExecStart=/usr/local/bin/fydelguard
Restart=on-failure
RestartSec=10
User=root
Group=root
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/var/lib/fydelguard /var/log/fydelguard

[Install]
WantedBy=multi-user.target
SERVICEEOF

# 4. Cria arquivos DEBIAN e dependências de runtime robustas
echo "[4/5] 📝 Criando metadados e definindo dependências do pacote..."

cat > "${DEB_DIR}/DEBIAN/control" << CTLEOF
Package: fydelguard
Version: ${APP_VERSION}
Section: security
Priority: optional
Architecture: ${ARCH}
Depends: clamav, clamav-daemon, clamav-freshclam, ufw, libsqlite3-0 (>= 3.30), libqt5widgets5 (>= 5.15), libqt5gui5 (>= 5.15), libqt5core5a (>= 5.15), libqt5svg5
Recommends: qt5-qmake
Maintainer: Adiel Santos Fontes <adiel@fydelistech.com>
Description: FydelGuard - Antivírus Profissional para FydelisTech
 Proteção avançada com ClamAV, monitoramento em tempo real
 com fanotify, firewall UFW integrado e interface gráfica Qt.
 .
 Recursos:
  * Varredura de arquivos e diretórios com ClamAV
  * Monitoramento em tempo real com fanotify
  * Quarentena com SQLite
  * Firewall UFW integrado
  * Atualização automática de assinaturas
  * Interface gráfica responsiva e moderna
Homepage: https://github.com/fydelistech/fydelguard
CTLEOF

# postinst
cat > "${DEB_DIR}/DEBIAN/postinst" << 'POSTEOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        echo "🔧 Configurando FydelGuard..."

        chmod 750 /var/lib/fydelguard/quarantine
        chmod 755 /var/lib/fydelguard
        chmod 755 /var/log/fydelguard

        if command -v gtk-update-icon-cache &>/dev/null; then
            gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
        fi

        if command -v update-desktop-database &>/dev/null; then
            update-desktop-database /usr/share/applications/ 2>/dev/null || true
        fi

        systemctl daemon-reload 2>/dev/null || true

        echo "✅ FydelGuard configurado com sucesso!"
        echo "ℹ️  Execute 'fydelguard' ou ative o serviço: systemctl start fydelguard"
        ;;
esac
POSTEOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# prerm
cat > "${DEB_DIR}/DEBIAN/prerm" << 'PREEOF'
#!/bin/bash
set -e

case "$1" in
    remove|purge)
        echo "🗑️  Parando serviço FydelGuard..."
        systemctl stop fydelguard.service 2>/dev/null || true
        systemctl disable fydelguard.service 2>/dev/null || true
        ;;
esac
PREEOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

echo "/etc/fydelguard/fydelguard.conf" > "${DEB_DIR}/DEBIAN/conffiles"

# 5. Empacota
echo "[5/5] 📦 Gerando .deb..."
fakeroot dpkg-deb --build "${DEB_DIR}" 2>/dev/null || dpkg-deb --build "${DEB_DIR}"

echo ""
echo "✅ Pacote criado com sucesso: ${DEB_DIR}.deb"
