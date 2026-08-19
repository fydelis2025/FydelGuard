#ifndef GUARDVIEW_H
#define GUARDVIEW_H

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QProgressBar>
#include <QLineEdit>
#include <memory>

class Scanner;
class ScanWorker;
class RealTimeMonitor;
class QuarantineManager;
class Updater;
class FirewallManager;

class GuardView : public QMainWindow {
    Q_OBJECT

public:
    explicit GuardView(QWidget* parent = nullptr);
    ~GuardView();

private slots:
    void delayedInit();
    void switchPage(int row);
    void onScanFile();
    void onScanDir();
    void onStopScan();
    void onRefreshFirewall();
    void onToggleFirewall();
    void onAddRule();
    void onDeleteRule();
    void onUpdateSignatures();

private:
    void setupUi();
    void applyStyle();
    
    // ✅ Declaração única das páginas e utilitários
    QWidget* createStatusPage();
    QWidget* createScanPage();
    QWidget* createMonitorPage();
    QWidget* createQuarantinePage();
    QWidget* createFirewallPage();
    QWidget* createSettingsPage();
    QWidget* createScrollablePage(QWidget* content);

    QListWidget* m_sidebar = nullptr;
    QStackedWidget* m_stackedPages = nullptr;

    std::unique_ptr<Scanner> m_scanner;
    std::unique_ptr<ScanWorker> m_worker;
    std::unique_ptr<RealTimeMonitor> m_realtime;
    std::unique_ptr<QuarantineManager> m_quarantine;
    std::unique_ptr<Updater> m_updater;
    std::unique_ptr<FirewallManager> m_firewall;

    QLabel* m_statusLabel = nullptr;
    QTableWidget* m_resultsTable = nullptr;
    QTableWidget* m_rulesTable = nullptr;
    QTableWidget* m_quarantineTable = nullptr;
    QPushButton* m_btnScanFile = nullptr;
    QPushButton* m_btnScanDir = nullptr;
    QPushButton* m_btnStop = nullptr;
    QPushButton* m_btnToggleFW = nullptr;
    QLineEdit* m_editPort = nullptr;
    QLineEdit* m_editIp = nullptr;
};

#endif
