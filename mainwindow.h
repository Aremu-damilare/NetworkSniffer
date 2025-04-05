#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <pcap.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class PacketSniffer : public QThread {
    Q_OBJECT

public:
    explicit PacketSniffer(const std::string &device, QObject *parent = nullptr); // FIXED
    void run() override;
    void stop();

signals:
    void packetCaptured(QString packetInfo);

private:
    bool running;
    std::string selectedDevice;  // Add this to store the selected device
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_startButton_clicked();
    void displayPacket(QString packetInfo);

private:
    Ui::MainWindow *ui;
    PacketSniffer *sniffer;
};

#endif // MAINWINDOW_H
