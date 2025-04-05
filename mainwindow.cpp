#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QInputDialog>
#include <QMessageBox>
#include <QString>
#include <iostream>
#include <pcap.h>
#include <winsock2.h>  // Windows-specific networking

#pragma comment(lib, "Ws2_32.lib")

// Define headers for Windows
struct ether_header {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct ip_header {
    u_char  ip_header_len:4, ip_version:4;
    u_char  tos;
    u_short total_length;
    u_short id;
    u_short frag_offset;
    u_char  ttl;
    u_char  protocol;
    u_short checksum;
    u_char  source_ip[4];
    u_char  dest_ip[4];
};

struct tcp_header {
    u_short source_port;
    u_short dest_port;
    u_int   seq;
    u_int   ack;
    u_char  data_offset;
    u_char  flags;
    u_short window;
    u_short checksum;
    u_short urgent_pointer;
};

// PacketSniffer class implementation
PacketSniffer::PacketSniffer(const std::string &device, QObject *parent)
    : QThread(parent), running(true), selectedDevice(device) {}

void PacketSniffer::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(selectedDevice.c_str(), 65536, 1, 1000, errbuf);

    if (!handle) {
        emit packetCaptured("Error opening device.");
        return;
    }

    // Packet processing callback
    auto packetHandler = [](u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        auto *sniffer = reinterpret_cast<PacketSniffer *>(user);

        if (pkthdr->len < sizeof(ether_header)) {
            emit sniffer->packetCaptured("Captured packet too short.");
            return;
        }

        // Extract Ethernet header
        const struct ether_header *eth = reinterpret_cast<const struct ether_header *>(packet);
        if (ntohs(eth->ether_type) != 0x0800) return;  // Only process IPv4

        // Extract IP header
        const struct ip_header *ip = reinterpret_cast<const struct ip_header *>(packet + sizeof(ether_header));
        if (ip->protocol != 6) return;  // Only process TCP

        int ipHeaderSize = ip->ip_header_len * 4;
        const struct tcp_header *tcp = reinterpret_cast<const struct tcp_header *>(packet + sizeof(ether_header) + ipHeaderSize);
        int tcpHeaderSize = (tcp->data_offset >> 4) * 4;

        // Calculate the start of the payload (HTTP data)
        const u_char *payload = packet + sizeof(ether_header) + ipHeaderSize + tcpHeaderSize;
        int payloadLength = pkthdr->len - (sizeof(ether_header) + ipHeaderSize + tcpHeaderSize);

        if (payloadLength > 0) {
            std::string data(reinterpret_cast<const char *>(payload), payloadLength);
            size_t hostPos = data.find("Host: ");
            size_t getPos = data.find("GET ");

            if (getPos != std::string::npos && hostPos != std::string::npos) {
                size_t hostEnd = data.find("\r\n", hostPos);
                size_t getEnd = data.find(" ", getPos + 4);

                if (hostEnd != std::string::npos && getEnd != std::string::npos) {
                    std::string host = data.substr(hostPos + 6, hostEnd - (hostPos + 6));
                    std::string urlPath = data.substr(getPos + 4, getEnd - (getPos + 4));

                    QString fullUrl = QString("Captured URL: http://%1%2").arg(QString::fromStdString(host)).arg(QString::fromStdString(urlPath));
                    emit sniffer->packetCaptured(fullUrl);
                }
            }
        }
    };

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char *>(this));

    pcap_close(handle);
}

void PacketSniffer::stop() {
    running = false;
    terminate();  // Forcefully stop the thread if needed
}

// MainWindow class implementation
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow), sniffer(nullptr) {
    ui->setupUi(this);
}

MainWindow::~MainWindow() {
    delete ui;
    if (sniffer) {
        sniffer->stop();
        sniffer->wait();
        delete sniffer;
    }
}

void MainWindow::on_startButton_clicked() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        QMessageBox::critical(this, "Error", "Failed to retrieve network devices.");
        return;
    }

    // Store device names and descriptions
    QStringList deviceList;
    std::vector<std::string> rawDeviceList;
    for (device = alldevs; device; device = device->next) {
        QString description = device->description ? QString(device->description) : "No description";
        QString deviceInfo = QString("%1 - %2").arg(device->name, description);
        deviceList.append(deviceInfo);
        rawDeviceList.push_back(device->name);
    }

    // Ask the user to select a device
    bool ok;
    QString selectedDevice = QInputDialog::getItem(this, "Select Network Device",
                                                   "Available Devices:", deviceList, 0, false, &ok);

    if (!ok || selectedDevice.isEmpty()) {
        pcap_freealldevs(alldevs);
        return;
    }

    // Find the index of the selected device
    int selectedIndex = deviceList.indexOf(selectedDevice);
    if (selectedIndex < 0 || selectedIndex >= rawDeviceList.size()) {
        QMessageBox::critical(this, "Error", "Invalid device selection.");
        pcap_freealldevs(alldevs);
        return;
    }

    ui->packetTextEdit->append(QString("Selected Device: %1").arg(selectedDevice));

    // Clean up device list
    pcap_freealldevs(alldevs);

    // Stop previous sniffer if running
    if (sniffer) {
        sniffer->stop();
        sniffer->wait();
        delete sniffer;
    }

    // Start new sniffer with selected device
    sniffer = new PacketSniffer(rawDeviceList[selectedIndex], this);
    connect(sniffer, &PacketSniffer::packetCaptured, this, &MainWindow::displayPacket);
    sniffer->start();
}

void MainWindow::displayPacket(QString packetInfo) {
    ui->packetTextEdit->append(packetInfo); // Display captured URLs
}
