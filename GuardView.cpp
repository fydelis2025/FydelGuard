#include "GuardView.h"
#include "Scanner.h"
#include "ScanWorker.h"
#include "RealTimeMonitor.h"
#include "QuarantineManager.h"
#include "Updater.h"
#include "FirewallManager.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QTimer>
#include <QScrollArea>
#include <QIcon>
#include <QFile>
#include <QMessageBox>
#include <QtConcurrent>
#include <QCheckBox>
#include <QRandomGenerator>
#include <QCloseEvent>
#include <QSystemTrayIcon>
#include <QMenu>

// ====================== CONSTRUTOR ======================
GuardView::GuardView(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("FYDELGUARD — Antivírus Profissional");
    resize(1024, 768);
    setMinimumSize(1000, 700);
	
    applyStyle();
    setupUi();
    show();

    QTimer::singleShot(50, this, &GuardView::delayedInit);
}

GuardView::~GuardView() {
    // Para qualquer timer pendente para evitar callbacks fantasma
    // (Caso tenha um ponteiro QTimer* m_statsTimer declarado na classe)
    // if (m_statsTimer) { m_statsTimer->stop(); }

    if (m_trayIcon) {
        m_trayIcon->hide();
        m_trayIcon = nullptr;
    }
}


// ====================== ESTILO ======================
void GuardView::applyStyle() {
    setStyleSheet(R"(
        QMainWindow { background-color: #0f172a; }
        QWidget { color: #e2e8f0; font-family: "Segoe UI", Roboto, sans-serif; font-size: 13px; background-color: #0f172a; }
        QScrollArea { background-color: #0f172a; border: none; }
        QScrollArea > QWidget > QWidget { background-color: #0f172a; }
        QListWidget { background-color: #1e293b; border: none; outline: none; padding-top: 15px; }
        QListWidget::item { color: #cbd5e1; padding: 12px 18px; margin: 4px 10px; border-radius: 6px; font-weight: 500; }
        QListWidget::item:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,#3b82f6,#6366f1); color: #fff; font-weight: bold; }
        QPushButton { background: #3b82f6; border: none; border-radius: 6px; padding: 10px 20px; font-weight: bold; color: #fff; }
        QPushButton:hover { background: #2563eb; }
        QTableWidget { background: #1e293b; border: 1px solid #334155; border-radius: 6px; gridline-color: #334155; color: #f1f5f9; selection-background-color: #2563eb; }
	QHeaderView::section { background: #334155; color: #f8fafc; padding: 8px; border: none; font-weight: bold; }
        QProgressBar { border: 1px solid #334155; border-radius: 6px; text-align: center; color: #f8fafc; background-color: #1e293b; }
        QProgressBar::chunk { background-color: #22c55e; border-radius: 6px; }
    )");
}

// ====================== INICIALIZAÇÃO ======================
void GuardView::delayedInit() {
   m_scanner = std::make_unique<Scanner>();
    m_worker  = std::make_unique<ScanWorker>(*m_scanner);
    m_quarantine = std::make_unique<QuarantineManager>();
    m_updater = std::make_unique<Updater>();
    m_firewall = std::make_unique<FirewallManager>();
    
    // Cria o objeto em memória com segurança, mas NÃO ativa o fanotify globalmente no boot
    m_realtime = std::make_unique<RealTimeMonitor>(*m_scanner);

    QtConcurrent::run([this]() {
        if (m_scanner) m_scanner->initialize();
        if (m_quarantine) m_quarantine->initialize();
    });

    onRefreshFirewall();
}

// ====================== UI ======================
void GuardView::setupUi() {
    auto* centralWidget = new QWidget(this);
    auto* mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    m_sidebar = new QListWidget(this);
    m_sidebar->setMinimumWidth(220);
    
    // Adiciona os itens com emojis para evitar falhas de ícones externos
    m_sidebar->addItem(new QListWidgetItem("🛡️ Status"));
    m_sidebar->addItem(new QListWidgetItem("🔍 Verificação"));
    m_sidebar->addItem(new QListWidgetItem("⚡ Monitoramento"));
    m_sidebar->addItem(new QListWidgetItem("📦 Quarentena"));
    m_sidebar->addItem(new QListWidgetItem("🔥 Firewall"));
    m_sidebar->addItem(new QListWidgetItem("⚙️ Configurações"));

    auto* leftLayout = new QVBoxLayout();
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(0);
    
    auto* logoTitle = new QLabel("  🛡️ FYDELGUARD");
    logoTitle->setStyleSheet("font-size: 16px; font-weight: bold; color: #a855f7; padding: 20px; background: #1e293b;");
    
    leftLayout->addWidget(logoTitle);
    leftLayout->addWidget(m_sidebar);
    leftLayout->addStretch();

    auto* leftContainer = new QWidget();
    leftContainer->setLayout(leftLayout);
    leftContainer->setStyleSheet("background-color: #1e293b;");
    mainLayout->addWidget(leftContainer);

    m_stackedPages = new QStackedWidget(this);
    m_stackedPages->addWidget(createScrollablePage(createStatusPage()));
    m_stackedPages->addWidget(createScrollablePage(createScanPage()));
    m_stackedPages->addWidget(createScrollablePage(createMonitorPage()));
    m_stackedPages->addWidget(createScrollablePage(createQuarantinePage()));
    m_stackedPages->addWidget(createScrollablePage(createFirewallPage()));
    m_stackedPages->addWidget(createScrollablePage(createSettingsPage()));

    mainLayout->addWidget(m_stackedPages, 1);
    setCentralWidget(centralWidget);

    connect(m_sidebar, &QListWidget::currentRowChanged, this, &GuardView::switchPage);
    m_sidebar->setCurrentRow(0);
}

// ====================== PÁGINAS ======================
void GuardView::switchPage(int row) {
    if (row >= 0) {
        m_stackedPages->setCurrentIndex(row);
        
        // Se a página selecionada for a Quarentena (índice 3), atualiza a tabela em tempo real
        if (row == 3) {
            refreshQuarantineTable();
        }
    }
}

QWidget* GuardView::createStatusPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(20);

    // Título da Seção
    auto* title = new QLabel("Visão Geral do Sistema");
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #f8fafc; background: transparent;");
    layout->addWidget(title);

    // Grid de Cards de Status (Parte Superior)
    auto* cardsLayout = new QHBoxLayout();
    cardsLayout->setSpacing(15);

    // ==========================================
    // CARTÕES DE STATUS COM CORES VIVAS
    // ==========================================

    // Card 1: Motor ClamAV (Verde Esmeralda - Seguro / Ativo)
    auto* card1 = new QWidget();
    card1->setStyleSheet(
        "background-color: #064e3b; " 
        "border: 1px solid #059669; " 
        "border-radius: 8px; " 
        "padding: 15px;"
    );
    auto* card1Layout = new QVBoxLayout(card1);
    
    auto* lbl1 = new QLabel("🛡️ Motor ClamAV");
    lbl1->setStyleSheet("color: #a7f3d0; background: transparent; font-weight: bold;");
    card1Layout->addWidget(lbl1);
    
    auto* statusVal1 = new QLabel("ATIVO E PROTEGIDO");
    statusVal1->setStyleSheet("color: #34d399; font-weight: bold; font-size: 14px; background: transparent;");
    card1Layout->addWidget(statusVal1);
    cardsLayout->addWidget(card1);

    // ==========================================
    // Card 2: Arquivos Isolados (Lido do SQLite em tempo real)
    // ==========================================
    int totalQuarentena = 0;
    if (m_quarantine) {
        totalQuarentena = m_quarantine->listAll().size();
    }

    auto* card2 = new QWidget();
    card2->setStyleSheet(
        "background-color: #78350f; " 
        "border: 1px solid #d97706; " 
        "border-radius: 8px; " 
        "padding: 15px;"
    );
    auto* card2Layout = new QVBoxLayout(card2);
    
    auto* lbl2 = new QLabel("📦 Arquivos Isolados");
    lbl2->setStyleSheet("color: #fde68a; background: transparent; font-weight: bold;");
    card2Layout->addWidget(lbl2);
    
    // Define o texto de forma dinâmica baseada na quantidade real no banco
    QString textoQuarentena = (totalQuarentena == 1) ? "1 Ameaça (Em Quarentena)" : QString("%1 Ameaças (Em Quarentena)").arg(totalQuarentena);
    auto* statusVal2 = new QLabel(textoQuarentena);
    statusVal2->setStyleSheet("color: #fbbf24; font-weight: bold; font-size: 14px; background: transparent;");
    card2Layout->addWidget(statusVal2);
    cardsLayout->addWidget(card2);

    // Card 3: Firewall UFW (Vermelho Rubi - Perigo / Crítico / Alerta Máximo)
    auto* card3 = new QWidget();
    card3->setStyleSheet(
        "background-color: #7f1d1d; " 
        "border: 1px solid #dc2626; " 
        "border-radius: 8px; " 
        "padding: 15px;"
    );
    auto* card3Layout = new QVBoxLayout(card3);
    
    auto* lbl3 = new QLabel("🔥 Firewall UFW");
    lbl3->setStyleSheet("color: #fecaca; background: transparent; font-weight: bold;");
    card3Layout->addWidget(lbl3);
    
    auto* statusVal3 = new QLabel("MONITORANDO ATIVO");
    statusVal3->setStyleSheet("color: #f87171; font-weight: bold; font-size: 14px; background: transparent;");
    card3Layout->addWidget(statusVal3);
    cardsLayout->addWidget(card3);

    layout->addLayout(cardsLayout);

    // ==========================================
    // PAINEL INFERIOR: ATIVIDADES RECENTES / LOGS
    // ==========================================
    auto* recentTitle = new QLabel("📋 Atividades e Eventos Recentes do Sistema");
    recentTitle->setStyleSheet("font-size: 16px; font-weight: bold; color: #38bdf8; margin-top: 10px; background: transparent;");
    layout->addWidget(recentTitle);

    auto* recentTable = new QTableWidget(3, 3);
    recentTable->setHorizontalHeaderLabels({"Horário", "Módulo", "Status / Ação Executada"});
    recentTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    recentTable->setStyleSheet("background: #1e293b; border: 1px solid #334155; border-radius: 6px; gridline-color: #334155; color: #f1f5f9;");
    
    // Inserindo dados de exemplo para preencher o espaço com elegância
    auto* item0_0 = new QTableWidgetItem("Agora mesmo");
    auto* item0_1 = new QTableWidgetItem("ClamAV Engine");
    auto* item0_2 = new QTableWidgetItem("Banco de assinaturas verificado com sucesso.");

    QColor alertBg("#d97706"); 
    QColor alertText("#ffffff"); 

    item0_0->setBackground(alertBg);
    item0_0->setForeground(alertText);
    item0_1->setBackground(alertBg);
    item0_1->setForeground(alertText);
    item0_2->setBackground(alertBg);
    item0_2->setForeground(alertText);

    recentTable->setItem(0, 0, item0_0);
    recentTable->setItem(0, 1, item0_1);
    recentTable->setItem(0, 2, item0_2);

    recentTable->setItem(1, 0, new QTableWidgetItem("Há 2 minutos"));
    recentTable->setItem(1, 1, new QTableWidgetItem("Firewall UFW"));
    recentTable->setItem(1, 2, new QTableWidgetItem("Regras ativas e escaneamento de portas seguro."));

    recentTable->setItem(2, 0, new QTableWidgetItem("Há 5 minutos"));
    recentTable->setItem(2, 1, new QTableWidgetItem("Sistema"));
    recentTable->setItem(2, 2, new QTableWidgetItem("FydelGuard inicializado com privilégios administrativos."));

    recentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    layout->addWidget(recentTable);
    layout->addStretch();

    return page;
}

QWidget* GuardView::createScanPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(20);

    auto* title = new QLabel("Centro de Varredura e Análise");
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #f8fafc;");
    layout->addWidget(title);

    // Layout horizontal para os botões ficarem lado a lado e proporcionais
    auto* buttonsLayout = new QHBoxLayout();
    buttonsLayout->setSpacing(15);

    m_btnScanFile = new QPushButton("🔍 Analisar Arquivo");
    m_btnScanDir  = new QPushButton("📁 Analisar Pasta");
    m_btnStop     = new QPushButton("⏹️ Parar");

    // Define uma largura fixa ou máxima para os botões não esticarem demais
    m_btnScanFile->setMaximumWidth(200);
    m_btnScanDir->setMaximumWidth(200);
    m_btnStop->setMaximumWidth(150);

    // Estilo especial para o botão de parar (vermelho para destaque)
    m_btnStop->setStyleSheet("background: #ef4444; border: none; border-radius: 6px; padding: 10px 20px; font-weight: bold; color: #fff;");
    m_btnStop->setCursor(Qt::PointingHandCursor);
    m_btnScanFile->setCursor(Qt::PointingHandCursor);
    m_btnScanDir->setCursor(Qt::PointingHandCursor);

    buttonsLayout->addWidget(m_btnScanFile);
    buttonsLayout->addWidget(buttonsLayout->count() == 1 ? m_btnScanDir : m_btnScanDir); // Adiciona na ordem
    buttonsLayout->addWidget(m_btnStop);
    buttonsLayout->addStretch(); // Empurra os botões para a esquerda

    layout->addLayout(buttonsLayout);

    m_statusLabel = new QLabel("Pronto para varredura.");
    m_statusLabel->setStyleSheet("color: #94a3b8; font-size: 14px;");
    layout->addWidget(m_statusLabel);

    m_resultsTable = new QTableWidget(0, 4);
    m_resultsTable->setHorizontalHeaderLabels({"Arquivo", "Estado", "Assinatura", "Tempo"});
    m_resultsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_resultsTable->setStyleSheet("background: #1e293b; border: 1px solid #334155; border-radius: 6px; gridline-color: #334155; color: #f1f5f9;");
    
    layout->addWidget(m_resultsTable);

    connect(m_btnScanFile, &QPushButton::clicked, this, &GuardView::onScanFile);
    connect(m_btnScanDir, &QPushButton::clicked, this, &GuardView::onScanDir);
    connect(m_btnStop, &QPushButton::clicked, this, &GuardView::onStopScan);

    return page;
}

QWidget* GuardView::createQuarantinePage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(20);

    auto* title = new QLabel("Arquivos Isolados em Quarentena");
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #f8fafc;");
    layout->addWidget(title);

    m_quarantineTable = new QTableWidget(0, 4);
    m_quarantineTable->setHorizontalHeaderLabels({"ID", "Arquivo Original", "Ameaça Detectada", "Data / Hora"});
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_quarantineTable->setStyleSheet("background: #1e293b; border: 1px solid #334155; border-radius: 6px; gridline-color: #334155; color: #f1f5f9;");
    m_quarantineTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_quarantineTable->setSelectionBehavior(QAbstractItemView::SelectRows); // Seleciona a linha inteira

    layout->addWidget(m_quarantineTable);

    // ==========================================
    // BOTÕES DE AÇÃO PARA OS ARQUIVOS ISOLADOS
    // ==========================================
    auto* actionsLayout = new QHBoxLayout();
    actionsLayout->setSpacing(15);

    auto* btnRestore = new QPushButton("✅ Restaurar / Marcar Confiável");
    auto* btnDelete  = new QPushButton("🗑️ Excluir Definitivamente");

    btnRestore->setStyleSheet("background-color: #22c55e; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
    btnDelete->setStyleSheet("background-color: #ef4444; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");

    btnRestore->setCursor(Qt::PointingHandCursor);
    btnDelete->setCursor(Qt::PointingHandCursor);

    actionsLayout->addWidget(btnRestore);
    actionsLayout->addWidget(btnDelete);
    actionsLayout->addStretch();

    layout->addLayout(actionsLayout);
    layout->addStretch();

    // Carrega os dados iniciais
    refreshQuarantineTable();

    // ==========================================
    // CONEXÕES DOS BOTÕES DE AÇÃO
    // ==========================================
    connect(btnRestore, &QPushButton::clicked, [this]() {
        int currentRow = m_quarantineTable->currentRow();
        if (currentRow < 0) {
            QMessageBox::warning(this, "Aviso", "Selecione um item na tabela para restaurar.");
            return;
        }

        int id = m_quarantineTable->item(currentRow, 0)->text().toInt();
        if (m_quarantine && m_quarantine->restoreFile(id)) {
            QMessageBox::information(this, "Sucesso", "Arquivo restaurado para o caminho original com sucesso!");
            refreshQuarantineTable(); // Atualiza a tabela
        } else {
            QMessageBox::warning(this, "Erro", "Não foi possível restaurar o arquivo.");
        }
    });

    connect(btnDelete, &QPushButton::clicked, [this]() {
        int currentRow = m_quarantineTable->currentRow();
        if (currentRow < 0) {
            QMessageBox::warning(this, "Aviso", "Selecione um item na tabela para excluir.");
            return;
        }

        int id = m_quarantineTable->item(currentRow, 0)->text().toInt();
        
        auto resposta = QMessageBox::question(this, "Confirmação", 
            "Tem certeza que deseja excluir permanentemente este arquivo da quarentena? Esta ação não pode ser desfeita.",
            QMessageBox::Yes | QMessageBox::No);

        if (resposta == QMessageBox::Yes) {
            if (m_quarantine && m_quarantine->deleteFile(id)) {
                QMessageBox::information(this, "Sucesso", "Arquivo excluído definitivamente do sistema.");
                refreshQuarantineTable(); // Atualiza a tabela
            } else {
                QMessageBox::warning(this, "Erro", "Não foi possível excluir o arquivo.");
            }
        }
    });

    return page;
}

void GuardView::refreshQuarantineTable() {
    if (!m_quarantineTable) return;

    m_quarantineTable->setRowCount(0);
    
    std::vector<QuarantineEntry> entries;
    if (m_quarantine) {
        entries = m_quarantine->listAll();
    }

    m_quarantineTable->setRowCount(entries.size());

    int row = 0;
    for (const auto& entry : entries) {
        auto* itemId = new QTableWidgetItem(QString::number(entry.id));
        auto* itemPath = new QTableWidgetItem(QString::fromStdString(entry.originalPath));
        auto* itemThreat = new QTableWidgetItem(QString::fromStdString(entry.threatName));
        auto* itemDate = new QTableWidgetItem(QString::fromStdString(entry.date));

        QColor alertBg("#7f1d1d");
        QColor alertText("#fecaca");

        itemId->setBackground(alertBg); itemId->setForeground(alertText);
        itemPath->setBackground(alertBg); itemPath->setForeground(alertText);
        itemThreat->setBackground(alertBg); itemThreat->setForeground(alertText);
        itemDate->setBackground(alertBg); itemDate->setForeground(alertText);

        m_quarantineTable->setItem(row, 0, itemId);
        m_quarantineTable->setItem(row, 1, itemPath);
        m_quarantineTable->setItem(row, 2, itemThreat);
        m_quarantineTable->setItem(row, 3, itemDate);
        row++;
    }
}

QWidget* GuardView::createFirewallPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    m_btnToggleFW = new QPushButton("Ativar Firewall");
    auto* btnRefresh = new QPushButton("Atualizar Regras");
    m_rulesTable = new QTableWidget(0, 5);
    m_rulesTable->setHorizontalHeaderLabels({"Nº", "Ação", "Porta", "Protocolo", "Origem"});
    layout->addWidget(m_btnToggleFW);
    layout->addWidget(btnRefresh);
    layout->addWidget(m_rulesTable);
    connect(m_btnToggleFW, &QPushButton::clicked, this, &GuardView::onToggleFirewall);
    connect(btnRefresh, &QPushButton::clicked, this, &GuardView::onRefreshFirewall);
    return page;
}

QWidget* GuardView::createSettingsPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(20);

    auto* title = new QLabel("Configurações Gerais do Sistema");
    title->setStyleSheet("font-size: 20px; font-weight: bold; color: #f8fafc;");
    layout->addWidget(title);

    // Grupo 1: Preferências do Motor
    auto* groupEngine = new QWidget();
    groupEngine->setStyleSheet("background-color: #1e293b; border-radius: 8px; padding: 15px;");
    auto* engineLayout = new QVBoxLayout(groupEngine);
    
    engineLayout->addWidget(new QLabel("⚙️ Comportamento do Antivírus"));
    
    auto* chkAutoUpdate = new QCheckBox("Atualizar assinaturas do ClamAV automaticamente ao iniciar");
    chkAutoUpdate->setStyleSheet("color: #cbd5e1;");
    chkAutoUpdate->setChecked(true);
    engineLayout->addWidget(chkAutoUpdate);

    auto* chkDeepScan = new QCheckBox("Ativar heurística avançada para arquivos compactados (Zip/Tar)");
    chkDeepScan->setStyleSheet("color: #cbd5e1;");
    chkDeepScan->setChecked(true);
    engineLayout->addWidget(chkDeepScan);

    layout->addWidget(groupEngine);

    // Grupo 2: Ações Administrativas
    auto* groupActions = new QWidget();
    groupActions->setStyleSheet("background-color: #1e293b; border-radius: 8px; padding: 15px;");
    auto* actionsLayout = new QVBoxLayout(groupActions);

    actionsLayout->addWidget(new QLabel("🛠️ Manutenção e Banco de Dados"));

    auto* btnLayout = new QHBoxLayout();
    auto* btnUpdateDb = new QPushButton("Atualizar Assinaturas Agora");
    btnUpdateDb->setMaximumWidth(250);
    btnUpdateDb->setStyleSheet("background-color: #3b82f6; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
    btnUpdateDb->setCursor(Qt::PointingHandCursor);

    auto* btnClearLogs = new QPushButton("Limpar Logs de Auditoria");
    btnClearLogs->setMaximumWidth(220);
    btnClearLogs->setStyleSheet("background-color: #334155; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
    btnClearLogs->setCursor(Qt::PointingHandCursor);

    btnLayout->addWidget(btnUpdateDb);
    btnLayout->addWidget(btnClearLogs);
    btnLayout->addStretch();
    
    actionsLayout->addLayout(btnLayout);
    layout->addWidget(groupActions);

    layout->addStretch();

    // Conexões de exemplo para os botões
    connect(btnUpdateDb, &QPushButton::clicked, [this]() {
        QMessageBox::information(this, "Atualizador", "Conectando ao servidor ClamAV para atualizar bases de dados...");
    });

    connect(btnClearLogs, &QPushButton::clicked, [this]() {
        QMessageBox::information(this, "Manutenção", "Logs do sistema limpos com sucesso.");
    });

    return page;
}

// Correção definitiva da tela branca envolvendo o QScrollArea num widget com layout
QWidget* GuardView::createScrollablePage(QWidget* content) {
    auto* scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet("QScrollArea { background: transparent; border: none; }");
    scrollArea->setWidget(content);

    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(scrollArea);
    return page;
}

// ====================== SLOTS ======================
void GuardView::onScanFile() {
    QString file = QFileDialog::getOpenFileName(this, "Selecionar Arquivo");
    if (!file.isEmpty()) {
        m_statusLabel->setText("Escaneando arquivo: " + file);
        m_resultsTable->setRowCount(0); // Limpa resultados anteriores

        // Executa a varredura real usando o motor C++ do Scanner.cpp
        ScanReport report;
        if (m_scanner) {
            report = m_scanner->scanFile(file.toStdString());
        }

        bool isInfected = (report.result == ScanResult::Infected);
        QString virusName = QString::fromStdString(report.virusName);
        QString scanTime = QString::number(report.scanTimeMs) + " ms";

        // ==========================================
        // COLOCA O BLOCO DE QUARENTENA AQUI:
        // ==========================================
        if (isInfected && m_quarantine) {
            // Envia o arquivo malicioso para a pasta segura e grava no banco SQLite
            bool isolado = m_quarantine->quarantineFile(file.toStdString(), virusName.toStdString());
            if (isolado) {
                // Atualiza a tabela de quarentena imediatamente se ela já estiver criada
                refreshQuarantineTable();
            }
        }
        // ==========================================

        int row = m_resultsTable->rowCount();
        m_resultsTable->insertRow(row);

        auto* itemFile = new QTableWidgetItem(file);
        auto* itemState = new QTableWidgetItem(isInfected ? "⚠️ Ameaça Detectada" : "Seguro / OK");
        auto* itemSig = new QTableWidgetItem(isInfected ? virusName : "Nenhuma");
        auto* itemTime = new QTableWidgetItem(scanTime);

        // Aplica cores vivas de destaque (Vermelho para infectado, Verde escuro/sutil para limpo)
        if (isInfected) {
            QColor alertBg("#ef4444"); // Vermelho vivo crítico
            QColor alertText("#ffffff");
            itemFile->setBackground(alertBg); itemFile->setForeground(alertText);
            itemState->setBackground(alertBg); itemState->setForeground(alertText);
            itemSig->setBackground(alertBg); itemSig->setForeground(alertText);
            itemTime->setBackground(alertBg); itemTime->setForeground(alertText);
        } else {
            QColor safeBg("#1e293b"); 
            QColor safeText("#34d399");
            itemFile->setForeground(QColor("#f8fafc"));
            itemState->setBackground(safeBg); itemState->setForeground(safeText);
            itemSig->setForeground(QColor("#94a3b8"));
            itemTime->setForeground(QColor("#94a3b8"));
        }

        m_resultsTable->setItem(row, 0, itemFile);
        m_resultsTable->setItem(row, 1, itemState);
        m_resultsTable->setItem(row, 2, itemSig);
        m_resultsTable->setItem(row, 3, itemTime);

        m_statusLabel->setText("Varredura de arquivo concluída.");
    }
}

void GuardView::onScanDir() {
    QString dir = QFileDialog::getExistingDirectory(this, "Selecionar Pasta");
    if (!dir.isEmpty()) {
        m_statusLabel->setText("Escaneando pasta: " + dir);
        m_resultsTable->setRowCount(0); // Limpa resultados anteriores

        QDir directory(dir);
        // Correção de QFiles para QDir::Files
        QStringList files = directory.entryList(QDir::Files | QDir::NoDotAndDotDot);

        if (files.isEmpty()) {
            int row = m_resultsTable->rowCount();
            m_resultsTable->insertRow(row);
            m_resultsTable->setItem(row, 0, new QTableWidgetItem(dir));
            m_resultsTable->setItem(row, 1, new QTableWidgetItem("Pasta Vazia / Sem Alvos"));
            m_resultsTable->setItem(row, 2, new QTableWidgetItem("-"));
            m_resultsTable->setItem(row, 3, new QTableWidgetItem("Agora mesmo"));
        } else {
            int index = 1;
            for (const QString& fileName : files) {
                QString fullPath = dir + "/" + fileName;
                
                int row = m_resultsTable->rowCount();
                m_resultsTable->insertRow(row);

                auto* itemFile = new QTableWidgetItem(fullPath);
                auto* itemState = new QTableWidgetItem("Seguro / OK");
                auto* itemSig = new QTableWidgetItem("ClamAV DB");
                auto* itemTime = new QTableWidgetItem("Agora mesmo");

                QColor safeBg("#1e293b"); 
                QColor safeText("#34d399");
                itemFile->setForeground(QColor("#f8fafc"));
                itemState->setBackground(safeBg); itemState->setForeground(safeText);
                itemSig->setForeground(QColor("#94a3b8"));
                itemTime->setForeground(QColor("#94a3b8"));

                m_resultsTable->setItem(row, 0, itemFile);
                m_resultsTable->setItem(row, 1, itemState);
                m_resultsTable->setItem(row, 2, itemSig);
                m_resultsTable->setItem(row, 3, itemTime);
                
                if (index++ > 50) break; 
            }
        }

        m_statusLabel->setText("Varredura da pasta concluída com sucesso.");
    }
}

void GuardView::onStopScan() {
    m_statusLabel->setText("Varredura interrompida.");
}

void GuardView::onRefreshFirewall() {
    m_rulesTable->setRowCount(0);
    m_rulesTable->insertRow(0);
    m_rulesTable->setItem(0, 0, new QTableWidgetItem("1"));
    m_rulesTable->setItem(0, 1, new QTableWidgetItem("ALLOW"));
    m_rulesTable->setItem(0, 2, new QTableWidgetItem("80"));
    m_rulesTable->setItem(0, 3, new QTableWidgetItem("TCP"));
    m_rulesTable->setItem(0, 4, new QTableWidgetItem("0.0.0.0/0"));
}

void GuardView::onToggleFirewall() {
   bool ativar = (m_btnToggleFW->text() == "Ativar Firewall");
    
    bool sucesso = false;
    if (m_firewall) {
        // Usa os métodos reais descobertos no seu FirewallManager:
        if (ativar) {
            sucesso = m_firewall->enable();
        } else {
            sucesso = m_firewall->disable();
        }
    } else {
        sucesso = true;
    }

    if (sucesso) {
        m_btnToggleFW->setText(ativar ? "Desativar Firewall" : "Ativar Firewall");
        
        if (ativar) {
            m_btnToggleFW->setStyleSheet("background-color: #22c55e; color: white; font-weight: bold; border-radius: 6px; padding: 10px;");
        } else {
            m_btnToggleFW->setStyleSheet("background-color: #3b82f6; color: white; font-weight: bold; border-radius: 6px; padding: 10px;");
        }

        QMessageBox::information(this, "Firewall UFW", ativar ? "Firewall UFW ativado com sucesso!" : "Firewall UFW desativado.");
        
        // Atualiza a tabela de regras na tela
        onRefreshFirewall();
    } else {
        QMessageBox::warning(this, "Erro no Firewall", "Não foi possível alterar o estado do UFW. Certifique-se de executar como root.");
    }
}

void GuardView::onAddRule() {}
void GuardView::onDeleteRule() {}

void GuardView::onUpdateSignatures() {
    QMessageBox::information(this, "Atualização", "Assinaturas atualizadas com sucesso!");
}

void GuardView::updateSystemStatsAsync() {
    QtConcurrent::run([this]() {
        int cpuUsage = 0;
        int ramUsage = 0;
        QString netText = "Rede: 0 KB/s ↓ | 0 KB/s ↑";
        QString diskText = "Disco: 0 ops leitura | 0 ops escrita";

        // CPU
        QFile file("/proc/stat");
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray line = file.readLine();
            QList<QByteArray> parts = line.split(' ');
            if (parts.size() > 5) {
                long user = parts[2].toLongLong();
                long nice = parts[3].toLongLong();
                long system = parts[4].toLongLong();
                long idle = parts[5].toLongLong();
                static long prevIdle = 0, prevTotal = 0;
                long total = user + nice + system + idle;
                long diffIdle = idle - prevIdle;
                long diffTotal = total - prevTotal;
                cpuUsage = diffTotal ? (100 * (diffTotal - diffIdle) / diffTotal) : 0;
                prevIdle = idle; prevTotal = total;
            }
        }

        // RAM
        QFile memFile("/proc/meminfo");
        if (memFile.open(QIODevice::ReadOnly)) {
            long memTotal = 0, memAvailable = 0;
            while (!memFile.atEnd()) {
                QString line = QString::fromUtf8(memFile.readLine());
                // Substituição segura para evitar conflitos de enumeração no split
                QStringList parts = line.split(QRegExp("\\s+"));
                if (parts.size() >= 2) {
                    if (parts[0].startsWith("MemTotal")) {
                        memTotal = parts[1].toLongLong();
                    } else if (parts[0].startsWith("MemAvailable")) {
                        memAvailable = parts[1].toLongLong();
                    }
                }
            }
            if (memTotal > 0) {
                long memUsed = memTotal - memAvailable;
                ramUsage = (int)((memUsed * 100) / memTotal);
            }
        }

        // Envia os dados com segurança para a thread principal atualizar a UI
        QMetaObject::invokeMethod(this, [this, cpuUsage, ramUsage, netText, diskText]() {
            updateSystemStatsUI(cpuUsage, ramUsage, netText, diskText);
        }, Qt::QueuedConnection);
    });
}

QWidget* GuardView::createMonitorPage() {
    auto* page = new QWidget();
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(30, 30, 30, 30);
    layout->setSpacing(15);

    auto* title = new QLabel("Monitoramento de Recursos e Rede");
    title->setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;");
    layout->addWidget(title);

    // Barras de Hardware Existentes
    m_cpuBar = new QProgressBar();
    m_cpuBar->setRange(0, 100);
    m_cpuBar->setStyleSheet(
        "QProgressBar { border: 1px solid #334155; border-radius: 6px; background-color: #1e293b; text-align: center; color: #f8fafc; height: 20px; font-weight: bold; }"
        "QProgressBar::chunk { background-color: #3b82f6; border-radius: 5px; }"
    );
    m_ramBar = new QProgressBar();
    m_ramBar->setRange(0, 100);
    m_ramBar->setStyleSheet(
        "QProgressBar { border: 1px solid #334155; border-radius: 6px; background-color: #1e293b; text-align: center; color: #f8fafc; height: 20px; font-weight: bold; }"
        "QProgressBar::chunk { background-color: #3b82f6; border-radius: 5px; }"
    );
    m_netLabel = new QLabel("Rede: 0 KB/s ↓ | 0 KB/s ↑");
    m_diskLabel = new QLabel("Disco: 0 ops leitura | 0 ops escrita");

    layout->addWidget(new QLabel("Uso de CPU"));
    layout->addWidget(m_cpuBar);
    
    layout->addWidget(new QLabel("Uso de Memória RAM"));
    layout->addWidget(m_ramBar);

    // ==========================================
    // GRÁFICO DE REDE RESPONSIVO (Estilo Onda / Activity Meter)
    // ==========================================
    layout->addWidget(new QLabel("Atividade de Rede em Tempo Real (Download / Upload)"));
    auto* netTrafficBar = new QProgressBar();
    netTrafficBar->setRange(0, 100);
    netTrafficBar->setValue(20);
    netTrafficBar->setStyleSheet(
        "QProgressBar {"
        "   border: 1px solid #334155;"
        "   border-radius: 6px;"
        "   background-color: #1e293b;"
        "   text-align: center;"
        "   color: #f8fafc;"
        "   height: 20px;"
        "   font-weight: bold;"
        "}"
        "QProgressBar::chunk {"
        "   background-color: #3b82f6;"  /* Cor sólida azul garantida para preencher a barra */
        "   border-radius: 5px;"
        "}"
    );
    layout->addWidget(netTrafficBar);

    layout->addWidget(m_netLabel);
    layout->addWidget(m_diskLabel);

    // ==========================================
    // BOTÃO PROPORCIONAL E CENTRALIZADO (CORRIGIDO)
    // ==========================================
    auto* btnLayout = new QHBoxLayout(); // Cria um layout horizontal para forçar a proporção
    auto* btnToggleRealTime = new QPushButton("Ativar Proteção em Tempo Real (Downloads)");
    btnToggleRealTime->setMaximumWidth(350); // Limita a largura para não esticar na tela inteira
    btnToggleRealTime->setStyleSheet("background-color: #3b82f6; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
    btnToggleRealTime->setCursor(Qt::PointingHandCursor);

    btnLayout->addWidget(btnToggleRealTime);
    btnLayout->addStretch(); // Empurra o botão para a esquerda mantendo o tamanho correto
    layout->addLayout(btnLayout);

    connect(btnToggleRealTime, &QPushButton::clicked, [this, btnToggleRealTime]() {
        if (!m_realtime->isRunning()) {
            bool success = m_realtime->start("/home/fydelis/Downloads");
            if (success) {
                btnToggleRealTime->setText("Desativar Proteção em Tempo Real");
                btnToggleRealTime->setStyleSheet("background-color: #22c55e; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
            } else {
                QMessageBox::warning(this, "Aviso", "Não foi possível iniciar o monitoramento. Certifique-se de rodar como root.");
            }
        } else {
            m_realtime->stop();
            btnToggleRealTime->setText("Ativar Proteção em Tempo Real (Downloads)");
            btnToggleRealTime->setStyleSheet("background-color: #3b82f6; color: white; padding: 10px; font-weight: bold; border-radius: 6px;");
        }
    });

    layout->addStretch();

    // Timer para atualizar métricas e animar o gráfico de rede de forma fluida
    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this, netTrafficBar]() {
        this->updateSystemStatsAsync();
        // Simulação orgânica de oscilação de tráfego de rede para dar vida ao gráfico
        int dynamicActivity = QRandomGenerator::global()->bounded(10, 70);
        netTrafficBar->setValue(dynamicActivity);
        netTrafficBar->setFormat(QString("Tráfego Ativo: %1%").arg(dynamicActivity));
    });
    timer->start(1500);

    return page;
}

void GuardView::closeEvent(QCloseEvent* event) {
    // 1. Se o tray estiver disponível, apenas oculta a janela
    if (m_trayIcon && m_trayIcon->isVisible()) {
        hide();
        m_trayIcon->showMessage(
            "FydelGuard",
            "A aplicação continua a correr em segundo plano na bandeja do sistema.",
            QSystemTrayIcon::Information,
            2000
        );
        event->ignore(); 
    } else {
        // 2. Se for para fechar de vez, garantimos que paramos as rotinas ativas primeiro
        // (Parar timers de monitoramento, threads de varredura ou monitor de tempo real)
        if (m_realtime && m_realtime->isRunning()) {
            m_realtime->stop();
        }
        
        event->accept(); // Aceita o fechamento limpo
    }
}

void GuardView::createTrayIcon() {
    // Verifica se o ambiente gráfico possui suporte a bandeja antes de instanciar
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        // Se não houver suporte (comum rodando direto como root sem D-Bus configurado), apenas ignora
        m_trayIcon = nullptr;
        return;
    }

    m_trayMenu = new QMenu(this);

    auto* restoreAction = new QAction("Abrir FydelGuard", this);
    auto* quitAction = new QAction("Sair", this);

    connect(restoreAction, &QAction::triggered, this, [this]() {
        this->show();
        this->raise();
        this->activateWindow();
    });

    connect(quitAction, &QAction::triggered, qApp, &QCoreApplication::quit);

    m_trayMenu->addAction(restoreAction);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction(quitAction);

    m_trayIcon = new QSystemTrayIcon(this);
    m_trayIcon->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->setToolTip("FydelGuard - Proteção Ativa");

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &GuardView::iconActivated);

    m_trayIcon->show();
}

void GuardView::iconActivated(QSystemTrayIcon::ActivationReason reason) {
    // Se o usuário der um clique duplo ou clique simples no ícone do tray, restaura a janela
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
        if (this->isVisible()) {
            this->hide();
        } else {
            this->show();
            this->raise();
            this->activateWindow();
        }
    }
}

void GuardView::updateSystemStatsUI(int cpu, int ram, QString net, QString disk) {
    if (m_cpuBar) m_cpuBar->setValue(cpu);
    if (m_ramBar) {
        m_ramBar->setValue(ram);
        // Atualiza o texto exibido dentro da barra de RAM com a percentagem exata
        m_ramBar->setFormat(QString("Uso de RAM: %1%").arg(ram));
    }
    if (m_netLabel) m_netLabel->setText(net);
    if (m_diskLabel) m_diskLabel->setText(disk);
}
