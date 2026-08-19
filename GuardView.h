#ifndef GUARDVIEW_H
#define GUARDVIEW_H

#include <QMainWindow>
#include <QListWidget>
#include <QStackedWidget>
#include <QTableWidget>
#include <QProgressBar>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QMessageBox>
#include <QtConcurrent>
#include <memory>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>

class Scanner;
class ScanWorker;
class RealTimeMonitor;
class QuarantineManager;
class Updater;
class FirewallManager;
class QSystemTrayIcon;
class QMenu;

class GuardView : public QMainWindow {
    Q_OBJECT
    
protected:
    void closeEvent(QCloseEvent* event) override;
        
public:
    explicit GuardView(QWidget* parent = nullptr);
    ~GuardView();

private:
    QSystemTrayIcon* m_trayIcon;
    QMenu* m_trayMenu;

    void createTrayIcon();
private slots:
    void iconActivated(QSystemTrayIcon::ActivationReason reason);

private slots:
    void switchPage(int row);
    void onScanFile();
    void onScanDir();
    void onStopScan();
    void onRefreshFirewall();
    void onToggleFirewall();
    void onAddRule();
    void onDeleteRule();
    void onUpdateSignatures();

    void updateSystemStatsAsync();   // dispara thread
    void updateSystemStatsUI(int cpu, int ram, QString net, QString disk); // atualiza UI

private:
    void applyStyle();
    void delayedInit();
    void setupUi();
    void refreshQuarantineTable();

    QWidget* createStatusPage();
    QWidget* createScanPage();
    QWidget* createMonitorPage();
    QWidget* createQuarantinePage();
    QWidget* createFirewallPage();
    QWidget* createSettingsPage();
    QWidget* createScrollablePage(QWidget* content);

    QListWidget* m_sidebar;
    QStackedWidget* m_stackedPages;

    QPushButton* m_btnScanFile;
    QPushButton* m_btnScanDir;
    QPushButton* m_btnStop;
    QLabel* m_statusLabel;
    QTableWidget* m_resultsTable;

    QProgressBar* m_cpuBar;
    QProgressBar* m_ramBar;
    QLabel* m_netLabel;
    QLabel* m_diskLabel;

    QTableWidget* m_quarantineTable;
    QPushButton* m_btnToggleFW;
    QTableWidget* m_rulesTable;

    std::unique_ptr<Scanner> m_scanner;
    std::unique_ptr<ScanWorker> m_worker;
    std::unique_ptr<RealTimeMonitor> m_realtime;
    std::unique_ptr<QuarantineManager> m_quarantine;
    std::unique_ptr<Updater> m_updater;
    std::unique_ptr<FirewallManager> m_firewall;
};

#endif // GUARDVIEW_H

