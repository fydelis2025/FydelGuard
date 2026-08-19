#include "GuardView.h"
#include "Scanner.h"
#include "ScanWorker.h"
#include "RealTimeMonitor.h"
#include "QuarantineManager.h"
#include "Updater.h"
#include "FirewallManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>
#include <QScrollArea>


GuardView::GuardView(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("FYDELGUARD — Antivírus Profissional");
    resize(800, 600);       // 🔒 Tamanho padrão inicial ideal
    setMinimumSize(800, 600); // 🔒 Impede que encolha e quebre o layout

    applyStyle();
    setupUi();
    show();

    QTimer::singleShot(50, this, &GuardView::delayedInit);
}

GuardView::~GuardView() {}

void GuardView::delayedInit() {
    try {
        m_scanner = std::make_unique<Scanner>();
        m_worker  = std::make_unique<ScanWorker>(*m_scanner);
        m_realtime= std::make_unique<RealTimeMonitor>(*m_scanner);
        m_quarantine = std::make_unique<QuarantineManager>();
        m_updater = std::make_unique<Updater>();
        m_firewall = std::make_unique<FirewallManager>();

        m_scanner->initialize();
        m_quarantine->initialize();

        m_worker->setReportCallback([this](const ScanReport& r) {
            int row = m_resultsTable->rowCount();
            m_resultsTable->insertRow(row);
            m_resultsTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(r.filePath)));
            m_resultsTable->setItem(row, 1, new QTableWidgetItem(r.result == ScanResult::Clean ? "🟢 Limpo" : "🔴 INFECTADO"));
            m_resultsTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(r.virusName)));
            m_resultsTable->setItem(row, 3, new QTableWidgetItem(QString::number(r.scanTimeMs)));
        });

        m_worker->setFinishedCallback([this] {
            if(m_statusLabel) m_statusLabel->setText("Varredura concluída com sucesso.");
            if(m_btnScanFile) m_btnScanFile->setEnabled(true);
            if(m_btnScanDir) m_btnScanDir->setEnabled(true);
            if(m_btnStop) m_btnStop->setEnabled(false);
        });

        onRefreshFirewall();
    } catch (...) {
        // Tolerância a falhas na inicialização
    }
}

void GuardView::applyStyle() {
    setStyleSheet(R"(
        QMainWindow { background-color: #070b14; }
        QWidget { color: #f1f5f9; font-family: "Segoe UI", Roboto, sans-serif; font-size: 13px; }
        
        /* Sidebar Esquerda */
        QListWidget {
            background-color: #0b1120;
            border: none;
            outline: none;
            padding-top: 15px;
        }
        QListWidget::item {
            color: #94a3b8;
            padding: 14px 20px;
            margin: 4px 10px;
            border-radius: 8px;
            font-weight: 500;
        }
        QListWidget::item:selected {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, #4f46e5, #7c3aed);
            color: white;
            font-weight: bold;
        }
        QListWidget::item:hover:!selected {
            background-color: #1e293b;
            color: #e2e8f0;
        }

        /* Cards Principais / Painéis */
        QWidget#CardWidget {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 14px;
        }

        /* Botões Estilo Neon / Gradiente */
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, #6366f1, #8b5cf6);
            border: none;
            border-radius: 10px;
            padding: 12px 24px;
            font-weight: bold;
            color: white;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, #4f46e5, #7c3aed);
        }
        QPushButton:pressed {
            background: #4338ca;
        }
        QPushButton:disabled {
            background: #1e293b;
            color: #475569;
        }

        /* Tabelas */
        QTableWidget {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 10px;
            gridline-color: #1e293b;
        }
        QHeaderView::section {
            background: #1e293b;
            color: #f8fafc;
            padding: 10px;
            border: none;
            font-weight: bold;
        }
        
        /* Inputs e Barras */
        QLineEdit {
            background: #070b14;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 10px;
            color: white;
        }
        QLineEdit:focus { border-color: #6366f1; }
        
        QProgressBar {
            background: #070b14;
            border: 1px solid #1e293b;
            border-radius: 8px;
            text-align: center;
            height: 22px;
            color: white;
            font-weight: bold;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, #10b981, #6366f1);
            border-radius: 7px;
        }
    )");
}

void GuardView::setupUi() {
     auto* centralWidget = new QWidget(this);
    auto* mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // --- SIDEBAR ---
    m_sidebar = new QListWidget(this);
    m_sidebar->setMinimumWidth(180);
    m_sidebar->setMaximumWidth(260);
    m_sidebar->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    m_sidebar->addItem("🛡️  Status");
    m_sidebar->addItem("🔍  Verificação");
    m_sidebar->addItem("⚡  Proteção Real-Time");
    m_sidebar->addItem("📦  Quarentena");
    m_sidebar->addItem("🔥  Firewall");
    m_sidebar->addItem("⚙️  Configurações");

    auto* leftContainer = new QWidget();
    auto* leftLayout = new QVBoxLayout(leftContainer);
    leftLayout->setContentsMargins(0,0,0,0);
    leftLayout->setSpacing(0);

    auto* logoTitle = new QLabel("  🛡️ FYDELGUARD");
    logoTitle->setStyleSheet("font-size: 16px; font-weight: bold; color: #a855f7; padding: 20px; background: #0b1120;");
    auto* brandLabel = new QLabel("<b>FydelisTech</b><br><span style='color:#64748b; font-size:11px;'>Segurança Avançada</span>");
    brandLabel->setContentsMargins(20, 20, 20, 20);

    leftLayout->addWidget(logoTitle);
    leftLayout->addWidget(m_sidebar);
    leftLayout->addWidget(brandLabel);
    leftContainer->setStyleSheet("background-color: #0b1120;");

    mainLayout->addWidget(leftContainer);

    // --- PÁGINAS COM SCROLL ÁREA RESPONSIVO ---
    m_stackedPages = new QStackedWidget(this);
    m_stackedPages->addWidget(createScrollablePage(createStatusPage()));
    m_stackedPages->addWidget(createScanPage());      // já tem scroll interno se necessário
    m_stackedPages->addWidget(createMonitorPage());
    m_stackedPages->addWidget(createQuarantinePage());
    m_stackedPages->addWidget(createFirewallPage());
    m_stackedPages->addWidget(createSettingsPage());

    mainLayout->addWidget(m_stackedPages, 1); // stretch = 1 para expandir
    setCentralWidget(centralWidget);

    connect(m_sidebar, &QListWidget::currentRowChanged, this, &GuardView::switchPage);
    m_sidebar->setCurrentRow(0);
}

void GuardView::switchPage(int row) {
    if (row >= 0) {
        m_stackedPages->setCurrentIndex(row);
    }
}

// ==========================================
// MÉTODO AUXILIAR: Envolve qualquer página em um QScrollArea
// ==========================================
QWidget* GuardView::createScrollablePage(QWidget* content) {
    auto* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }"
                              "QScrollArea > QWidget > QWidget { background: transparent; }");
    scrollArea->setWidget(content);

    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(scrollArea);
    return page;
}

// ==========================================
// PÁGINA 1: STATUS (Dashboard Principal)
// ==========================================
QWidget* GuardView::createStatusPage() {
    auto* page = new QWidget();
    auto* mainLayout = new QVBoxLayout(page);
    mainLayout->setContentsMargins(25, 25, 25, 25);
    mainLayout->setSpacing(20);

    // 1. BANNER SUPERIOR DE PROTEÇÃO (Verde Neon)
    auto* bannerCard = new QWidget();
    bannerCard->setObjectName("CardWidget");
    bannerCard->setFixedHeight(130);
    auto* bannerLayout = new QHBoxLayout(bannerCard);
    
    auto* shieldIcon = new QLabel("🛡️");
    shieldIcon->setStyleSheet("font-size: 42px; background: transparent;");
    
    auto* bannerText = new QVBoxLayout();
    auto* subTitle = new QLabel("SEU SISTEMA ESTÁ");
    subTitle->setStyleSheet("font-size: 11px; color: #94a3b8; font-weight: bold; background: transparent;");
    auto* titleProt = new QLabel("PROTEGIDO");
    titleProt->setStyleSheet("font-size: 22px; font-weight: bold; color: #22c55e; background: transparent;");
    auto* descProt = new QLabel("FydelGuard está ativo e monitorando seu sistema\nÚltima atualização: 28/07/2025 22:45");
    descProt->setStyleSheet("color: #64748b; font-size: 11px; background: transparent;");
    
    bannerText->addWidget(subTitle);
    bannerText->addWidget(titleProt);
    bannerText->addWidget(descProt);
    
    bannerLayout->addWidget(shieldIcon);
    bannerLayout->addLayout(bannerText);
    bannerLayout->addStretch();

    mainLayout->addWidget(bannerCard);

    // 2. GRID DE 4 CARDS DE MÉTRICAS (Estatísticas do Meio)
    auto* metricsGrid = new QGridLayout();
    metricsGrid->setSpacing(15);

    auto createMetricCard = [](QString val, QString title, QString sub) {
        auto* w = new QWidget();
        w->setObjectName("CardWidget");
        auto* l = new QVBoxLayout(w);
        auto* v = new QLabel(val); v->setStyleSheet("color: #f8fafc; font-size: 20px; font-weight: bold; background: transparent;");
        auto* t = new QLabel(title); t->setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: bold; background: transparent;");
        auto* s = new QLabel(sub); s->setStyleSheet("color: #38bdf8; font-size: 10px; background: transparent;");
        l->addWidget(v); l->addWidget(t); l->addWidget(s);
        return w;
    };

    metricsGrid->addWidget(createMetricCard("0", "AMEAÇAS DETECTADAS", "Sistema seguro"), 0, 0);
    metricsGrid->addWidget(createMetricCard("0", "ARQUIVOS VERIFICADOS", "Hoje"), 0, 1);
    metricsGrid->addWidget(createMetricCard("00:00:00", "ÚLTIMA VERIFICAÇÃO", "Nenhuma verificação realizada"), 0, 2);
    metricsGrid->addWidget(createMetricCard("ATUALIZAÇÕES", "ATUALIZADO", "Banco de dados atualizado"), 0, 3);

    mainLayout->addLayout(metricsGrid);

    // 3. SEÇÃO INFERIOR: 3 COLUNAS
    auto* bottomGrid = new QHBoxLayout();
    bottomGrid->setSpacing(15);

    auto* scanCard = new QWidget();
    scanCard->setObjectName("CardWidget");
    auto* scanLayout = new QVBoxLayout(scanCard);
    auto* scanTitle = new QLabel("<b>VERIFICAÇÃO RÁPIDA</b><br><span style='color:#64748b; font-size:11px;'>Escaneia áreas críticas do sistema em busca de ameaças.</span>");
    auto* btnFastScan = new QPushButton("🔍 INICIAR VERIFICAÇÃO");
    btnFastScan->setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, #4f46e5, #9333ea); border-radius: 8px; padding: 12px; font-weight: bold;");
    scanLayout->addWidget(scanTitle);
    scanLayout->addStretch();
    scanLayout->addWidget(btnFastScan);

    auto* rtCard = new QWidget();
    rtCard->setObjectName("CardWidget");
    auto* rtLayout = new QVBoxLayout(rtCard);
    auto* rtTitle = new QLabel("<b>PROTEÇÃO EM TEMPO REAL</b><br><span style='color:#64748b; font-size:11px;'>Monitorando atividades e protegendo seu sistema.</span>");
    auto* rtList = new QLabel("📄 Proteção de Arquivos\n🧠 Proteção de Comportamento\n🌐 Proteção da Web\n✉️ Proteção de E-mail");
    rtList->setStyleSheet("color: #cbd5e1; font-size: 12px; background: transparent;");
    rtLayout->addWidget(rtTitle);
    rtLayout->addWidget(rtList);

    auto* actCard = new QWidget();
    actCard->setObjectName("CardWidget");
    auto* actLayout = new QVBoxLayout(actCard);
    auto* actTitle = new QLabel("<b>ATIVIDADE RECENTE</b><br><span style='color:#64748b; font-size:11px;'>Últimas ações realizadas pelo FydelGuard.</span>");
    auto* actList = new QLabel("✅ Sistema inicializado (22:45)\n✅ Banco atualizado v1.0.0 (22:45)\n🛡️ Proteção ativa (22:45)");
    actList->setStyleSheet("color: #cbd5e1; font-size: 11px; background: transparent;");
    actLayout->addWidget(actTitle);
    actLayout->addWidget(actList);

    bottomGrid->addWidget(scanCard, 1);
    bottomGrid->addWidget(rtCard, 1);
    bottomGrid->addWidget(actCard, 1);

    mainLayout->addLayout(bottomGrid);
    return page;
}

// ==========================================
// PÁGINA 2: VERIFICAÇÃO (Antivírus)
// ==========================================
QWidget* GuardView::createScanPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(15);

    auto* topRow = new QHBoxLayout();
    m_btnScanFile = new QPushButton("📄 Analisar Arquivo");
    m_btnScanDir  = new QPushButton("📁 Analisar Pasta");
    m_btnStop     = new QPushButton("⏹ Interromper");
    m_btnStop->setEnabled(false);
    m_statusLabel = new QLabel("Pronto para varredura.");

    topRow->addWidget(m_btnScanFile);
    topRow->addWidget(m_btnScanDir);
    topRow->addWidget(m_btnStop);
    topRow->addStretch();

    layout->addLayout(topRow);
    layout->addWidget(m_statusLabel);

    m_resultsTable = new QTableWidget(0, 4);
    m_resultsTable->setHorizontalHeaderLabels({"📂 Caminho do Arquivo", "📊 Estado", "⚠️ Assinatura", "⏱️ Tempo (ms)"});
    m_resultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    
    layout->addWidget(m_resultsTable);

    connect(m_btnScanFile, &QPushButton::clicked, this, &GuardView::onScanFile);
    connect(m_btnScanDir,  &QPushButton::clicked, this, &GuardView::onScanDir);
    connect(m_btnStop,     &QPushButton::clicked, this, &GuardView::onStopScan);

    return page;
}

// ==========================================
// PÁGINA 3: MONITORAMENTO (Real-Time)
// ==========================================
QWidget* GuardView::createMonitorPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(20);

    auto* lbl = new QLabel("🛡️ Proteção em Tempo Real (Fanotify)");
    lbl->setStyleSheet("font-size: 16px; font-weight: bold; color: #a855f7;");
    
    auto* btnUpdateSign = new QPushButton("🔄 Atualizar Banco de Assinaturas (Freshclam)");
    
    layout->addWidget(lbl);
    layout->addWidget(btnUpdateSign);
    layout->addStretch();

    connect(btnUpdateSign, &QPushButton::clicked, this, &GuardView::onUpdateSignatures);
    return page;
}

// ==========================================
// PÁGINA 4: QUARENTENA
// ==========================================
QWidget* GuardView::createQuarantinePage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    
    m_quarantineTable = new QTableWidget(0, 4);
    m_quarantineTable->setHorizontalHeaderLabels({"ID", "Arquivo Original", "Ameaça", "Data"});
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    
    layout->addWidget(new QLabel("📦 Arquivos Isolados em Quarentena"));
    layout->addWidget(m_quarantineTable);
    return page;
}

// ==========================================
// PÁGINA 5: FIREWALL
// ==========================================
QWidget* GuardView::createFirewallPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(15);

    auto* topLayout = new QHBoxLayout();
    m_btnToggleFW = new QPushButton("▶️ Ativar Firewall UFW");
    auto* btnRefresh = new QPushButton("🔃 Atualizar Regras");
    topLayout->addWidget(m_btnToggleFW);
    topLayout->addStretch();
    topLayout->addWidget(btnRefresh);
    layout->addLayout(topLayout);

    m_rulesTable = new QTableWidget(0, 5);
    m_rulesTable->setHorizontalHeaderLabels({"Nº", "Ação", "Porta", "Protocolo", "Origem / IP"});
    m_rulesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    layout->addWidget(m_rulesTable);

    auto* ruleBar = new QHBoxLayout();
    m_editPort = new QLineEdit(); m_editPort->setPlaceholderText("Porta (ex: 8080)");
    m_editIp = new QLineEdit(); m_editIp->setPlaceholderText("IP (vazio para todos)");
    auto* btnAdd = new QPushButton("➕ Adicionar Regra");
    auto* btnDel = new QPushButton("➖ Remover Regra");

    ruleBar->addWidget(m_editPort);
    ruleBar->addWidget(m_editIp);
    ruleBar->addWidget(btnAdd);
    ruleBar->addWidget(btnDel);
    layout->addLayout(ruleBar);

    connect(m_btnToggleFW, &QPushButton::clicked, this, &GuardView::onToggleFirewall);
    connect(btnRefresh, &QPushButton::clicked, this, &GuardView::onRefreshFirewall);
    connect(btnAdd, &QPushButton::clicked, this, &GuardView::onAddRule);
    connect(btnDel, &QPushButton::clicked, this, &GuardView::onDeleteRule);

    return page;
}

// ==========================================
// PÁGINA 6: CONFIGURAÇÕES
// ==========================================
QWidget* GuardView::createSettingsPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    
    auto* lbl = new QLabel("⚙️ Configurações Gerais do Sistema");
    lbl->setStyleSheet("font-size: 16px; font-weight: bold; color: #38bdf8;");
    layout->addWidget(lbl);
    
    auto* authorLbl = new QLabel("<b>FYDELGUARD</b> — Proteção Avançada para Automação Comercial<br>Autor: Adiel Santos Fontes | FydelisTech");
    authorLbl->setStyleSheet("color: #64748b; margin-top: 20px;");
    layout->addWidget(authorLbl);
    layout->addStretch();
    
    return page;
}

// --- MÉTODOS DE CONTROLE E AÇÕES ---
void GuardView::onScanFile() {
    if (!m_worker) return;
    QString path = QFileDialog::getOpenFileName(this, "Selecionar Arquivo");
    if (path.isEmpty()) return;
    m_resultsTable->setRowCount(0);
    m_btnScanFile->setEnabled(false);
    m_btnScanDir->setEnabled(false);
    m_btnStop->setEnabled(true);
    m_worker->enqueueScanFile(path.toStdString());
    m_statusLabel->setText("Varredura em andamento...");
}

void GuardView::onScanDir() {
    if (!m_worker) return;
    QString path = QFileDialog::getExistingDirectory(this, "Selecionar Pasta");
    if (path.isEmpty()) return;
    m_resultsTable->setRowCount(0);
    m_btnScanFile->setEnabled(false);
    m_btnScanDir->setEnabled(false);
    m_btnStop->setEnabled(true);
    m_worker->enqueueScanDir(path.toStdString(), true);
    m_statusLabel->setText("Varredura de diretório em andamento...");
}

void GuardView::onStopScan() {
    if (m_worker) m_worker->clearQueue();
    m_statusLabel->setText("Varredura interrompida.");
    m_btnScanFile->setEnabled(true);
    m_btnScanDir->setEnabled(true);
    m_btnStop->setEnabled(false);
}

void GuardView::onRefreshFirewall() {
    if (!m_firewall) return;
    m_rulesTable->setRowCount(0);
    auto rules = m_firewall->listRules();
    for (auto& r : rules) {
        int row = m_rulesTable->rowCount();
        m_rulesTable->insertRow(row);
        m_rulesTable->setItem(row, 0, new QTableWidgetItem(QString::number(r.number)));
        m_rulesTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(r.direction)));
        m_rulesTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(r.port)));
        m_rulesTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(r.protocol)));
        m_rulesTable->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(r.from)));
    }
    m_btnToggleFW->setText(m_firewall->isEnabled() ? "🛑 Desativar Firewall UFW" : "▶️ Ativar Firewall UFW");
}

void GuardView::onToggleFirewall() {
    if (!m_firewall) return;
    m_firewall->isEnabled() ? m_firewall->disable() : m_firewall->enable();
    onRefreshFirewall();
}

void GuardView::onAddRule() {
    if (!m_firewall) return;
    QString port = m_editPort->text().trimmed();
    QString ip   = m_editIp->text().trimmed();
    if (port.isEmpty()) return;
    m_firewall->addAllowRule(port.toStdString(), "tcp", ip.toStdString());
    m_editPort->clear(); m_editIp->clear();
    onRefreshFirewall();
}

void GuardView::onDeleteRule() {
    if (!m_firewall) return;
    int row = m_rulesTable->currentRow();
    if (row < 0) return;
    int num = m_rulesTable->item(row, 0)->text().toInt();
    m_firewall->deleteRule(num);
    onRefreshFirewall();
}

void GuardView::onUpdateSignatures() {
    if (m_updater) m_updater->updateClamAVSignatures();
}
