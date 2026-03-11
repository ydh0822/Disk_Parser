#include "ForensicImageExtractor/gui/MainWindow.h"

#include "ForensicImageExtractor/core/ImageReaderFactory.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"
#include "ForensicImageExtractor/workers/ExtractionWorker.h"
#include "ForensicImageExtractor/workers/ForensicsWorkers.h"

#include <QAction>
#include <QFileDialog>
#include <QHeaderView>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QSet>
#include <QSplitter>
#include <QStatusBar>
#include <QTableWidget>
#include <QTextEdit>
#include <QThread>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace fie::gui {
namespace {
constexpr int RolePartition = Qt::UserRole;
constexpr int RoleType = Qt::UserRole + 1;
constexpr int RolePath = Qt::UserRole + 2;
constexpr int RoleLoaded = Qt::UserRole + 3;
} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setupUi();
  setupMenu();
  connect(&m_logManager, &utils::LogManager::logAdded, this, &MainWindow::appendLog);
}

void MainWindow::setupUi() {
  setWindowTitle("Forensic Image Extractor");
  resize(1500, 900);

  auto *horizontal = new QSplitter(Qt::Horizontal, this);
  auto *leftPanel = new QWidget(horizontal);
  auto *leftLayout = new QVBoxLayout(leftPanel);

  m_partitionTree = new QTreeWidget(leftPanel);
  m_partitionTree->setHeaderLabel("Partitions / Directories");
  leftLayout->addWidget(m_partitionTree);

  m_fileTable = new QTableWidget(horizontal);
  m_fileTable->setColumnCount(15);
  m_fileTable->setHorizontalHeaderLabels({"Name", "Type", "Size", "Deleted", "MFT/Inode",
                                           "SI Created", "SI Modified", "SI Entry Modified",
                                           "SI Accessed", "FN Created", "FN Modified",
                                           "FN Entry Modified", "FN Accessed", "ADS",
                                           "Hash status"});
  m_fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  m_fileTable->setSelectionBehavior(QAbstractItemView::SelectRows);

  m_metadataPanel = new QTextEdit(horizontal);
  m_metadataPanel->setReadOnly(true);

  horizontal->addWidget(leftPanel);
  horizontal->addWidget(m_fileTable);
  horizontal->addWidget(m_metadataPanel);

  m_logPanel = new QPlainTextEdit(this);
  m_logPanel->setReadOnly(true);
  m_logPanel->setMaximumHeight(180);

  auto *vertical = new QSplitter(Qt::Vertical, this);
  vertical->addWidget(horizontal);
  vertical->addWidget(m_logPanel);
  setCentralWidget(vertical);

  connect(m_partitionTree, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onPartitionSelected);
  connect(m_fileTable, &QTableWidget::itemSelectionChanged, this, &MainWindow::onFileSelected);
}

void MainWindow::setupMenu() {
  auto *fileMenu = menuBar()->addMenu("&File");
  auto *toolsMenu = menuBar()->addMenu("&Tools");
  auto *helpMenu = menuBar()->addMenu("&Help");

  auto *openAction = fileMenu->addAction("Open Image");
  fileMenu->addAction("Close Image", [this]() {
    m_reader.reset();
    m_tskImage.reset();
    m_partitions.clear();
    m_files.clear();
    m_selectedPartitionIndex = -1;
    m_currentLogicalPath = "/";
    m_partitionTree->clear();
    m_fileTable->setRowCount(0);
  });
  fileMenu->addAction("Export Metadata Catalog", this, &MainWindow::onExportCatalog);
  fileMenu->addSeparator();
  fileMenu->addAction("Exit", this, &QWidget::close);

  toolsMenu->addAction("Settings");
  helpMenu->addAction("About", [this]() { QMessageBox::about(this, "About", "Forensic Image Extractor"); });

  auto *tb = addToolBar("Main");
  tb->addAction("Open image", this, &MainWindow::onOpenImage);
  tb->addAction("Refresh", this, &MainWindow::onPartitionSelected);
  tb->addAction("Extract selected", this, &MainWindow::onExtractSelected);
  tb->addAction("Export catalog", this, &MainWindow::onExportCatalog);
  m_stopAction = tb->addAction("Stop current task");
  m_stopAction->setEnabled(false);

  connect(openAction, &QAction::triggered, this, &MainWindow::onOpenImage);
}

void MainWindow::appendLog(const QString &line) { m_logPanel->appendPlainText(line); }
void MainWindow::setBusy(bool busy, const QString &message) {
  m_stopAction->setEnabled(busy);
  statusBar()->showMessage(message.isEmpty() ? (busy ? "Working..." : "Ready") : message);
}

void MainWindow::onOpenImage() {
  const auto path = QFileDialog::getOpenFileName(this, "Open Forensic Image");
  if (path.isEmpty()) return;

  auto createdReader = core::ImageReaderFactory::create(path);
  m_reader = std::shared_ptr<core::IImageReader>(std::move(createdReader));
  m_tskImage = std::make_shared<core::TskImageHandleAdapter>(m_reader);

  auto *thread = new QThread(this);
  auto *worker = new workers::ImageOpenWorker(m_reader, path);
  worker->moveToThread(thread);

  connect(thread, &QThread::started, worker, &workers::ImageOpenWorker::process);
  connect(worker, &workers::ImageOpenWorker::completed, this, [this, thread](bool ok, domain::ImageInfo info, const QString &error) {
    setBusy(false);
    if (!ok) {
      QMessageBox::critical(this, "Open image failed", error);
    } else {
      m_imageInfo = info;
      if (!m_reader->lastWarning().isEmpty()) {
        m_logManager.info(m_reader->lastWarning());
      }
      auto *partThread = new QThread(this);
      auto *partWorker = new workers::PartitionScanWorker(m_tskImage);
      partWorker->moveToThread(partThread);
      connect(partThread, &QThread::started, partWorker, &workers::PartitionScanWorker::process);
      connect(partWorker, &workers::PartitionScanWorker::completed, this,
              [this, partThread](std::vector<domain::PartitionInfo> parts, const QString &scanError, const QString &scanWarning) {
                setBusy(false);
                if (!scanWarning.isEmpty()) m_logManager.info(scanWarning);
                if (!scanError.isEmpty()) m_logManager.error(scanError);
                m_partitions = std::move(parts);
                populatePartitions();
                partThread->quit();
              });
      connect(partThread, &QThread::finished, partWorker, &QObject::deleteLater);
      connect(partThread, &QThread::finished, partThread, &QObject::deleteLater);
      setBusy(true, "Scanning partitions...");
      partThread->start();
    }
    thread->quit();
  });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);

  setBusy(true, "Opening image...");
  thread->start();
}

void MainWindow::populatePartitions() {
  m_partitionTree->clear();
  auto *root = new QTreeWidgetItem(m_partitionTree, {m_imageInfo.path});
  for (const auto &p : m_partitions) {
    auto *item = new QTreeWidgetItem(root, {QString("%1 [%2]").arg(p.identifier, p.description)});
    item->setData(0, RolePartition, p.index);
    item->setData(0, RoleType, "partition");
    item->setData(0, RolePath, "/");
    item->setData(0, RoleLoaded, false);
  }
  root->setExpanded(true);
}

void MainWindow::onPartitionSelected() {
  if (!m_tskImage || !m_tskImage->isOpen()) return;
  const auto items = m_partitionTree->selectedItems();
  if (items.isEmpty()) return;
  auto *selected = items.first();

  bool ok = false;
  const int index = selected->data(0, RolePartition).toInt(&ok);
  if (!ok || index < 0 || index >= static_cast<int>(m_partitions.size())) return;

  m_selectedPartitionIndex = index;
  m_currentLogicalPath = selected->data(0, RolePath).toString();
  if (m_currentLogicalPath.isEmpty()) m_currentLogicalPath = "/";

  auto *thread = new QThread(this);
  auto *worker = new workers::DirectoryListWorker(m_tskImage, m_partitions[index], m_currentLogicalPath);
  worker->moveToThread(thread);
  QPointer<QTreeWidgetItem> selectedGuard(selected);

  connect(thread, &QThread::started, worker, &workers::DirectoryListWorker::process);
  connect(worker, &workers::DirectoryListWorker::completed, this,
          [this, thread, selectedGuard](std::vector<domain::FileEntry> entries, const QString &error) {
            setBusy(false);
            if (!error.isEmpty()) m_logManager.error(error);
            m_files = std::move(entries);
            populateFiles(selectedGuard.data());
            thread->quit();
          });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);

  setBusy(true, QString("Enumerating %1 ...").arg(m_currentLogicalPath));
  thread->start();
}

void MainWindow::populateFiles(QTreeWidgetItem *selectedTreeItem) {
  m_fileTable->setRowCount(static_cast<int>(m_files.size()));
  auto dt = [](const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : ""; };

  for (int row = 0; row < static_cast<int>(m_files.size()); ++row) {
    const auto &f = m_files[row];
    m_fileTable->setItem(row, 0, new QTableWidgetItem(f.name));
    m_fileTable->setItem(row, 1, new QTableWidgetItem(f.isDirectory ? "Directory" : "File"));
    m_fileTable->setItem(row, 2, new QTableWidgetItem(QString::number(f.sizeBytes)));
    m_fileTable->setItem(row, 3, new QTableWidgetItem(f.isDeleted ? "Yes" : "No"));
    m_fileTable->setItem(row, 4, new QTableWidgetItem(QString::number(f.inode)));
    m_fileTable->setItem(row, 5, new QTableWidgetItem(dt(f.ntfs.standardInfo.created)));
    m_fileTable->setItem(row, 6, new QTableWidgetItem(dt(f.ntfs.standardInfo.modified)));
    m_fileTable->setItem(row, 7, new QTableWidgetItem(dt(f.ntfs.standardInfo.entryModified)));
    m_fileTable->setItem(row, 8, new QTableWidgetItem(dt(f.ntfs.standardInfo.accessed)));
    m_fileTable->setItem(row, 9, new QTableWidgetItem(dt(f.ntfs.fileNameInfo.created)));
    m_fileTable->setItem(row, 10, new QTableWidgetItem(dt(f.ntfs.fileNameInfo.modified)));
    m_fileTable->setItem(row, 11, new QTableWidgetItem(dt(f.ntfs.fileNameInfo.entryModified)));
    m_fileTable->setItem(row, 12, new QTableWidgetItem(dt(f.ntfs.fileNameInfo.accessed)));
    m_fileTable->setItem(row, 13, new QTableWidgetItem(f.ntfs.hasAds ? f.ntfs.adsNames.join(';') : "No"));
    m_fileTable->setItem(row, 14, new QTableWidgetItem("Not started"));
  }

  if (!selectedTreeItem) {
    return;
  }

  const bool alreadyLoaded = selectedTreeItem->data(0, RoleLoaded).toBool();
  if (alreadyLoaded) {
    return;
  }

  QSet<QString> existingPaths;
  for (int i = 0; i < selectedTreeItem->childCount(); ++i) {
    existingPaths.insert(selectedTreeItem->child(i)->data(0, RolePath).toString());
  }

  for (const auto &f : m_files) {
    if (!f.isDirectory) {
      continue;
    }
    if (existingPaths.contains(f.fullPath)) {
      continue;
    }
    auto *child = new QTreeWidgetItem(selectedTreeItem, {f.name});
    child->setData(0, RolePartition, m_selectedPartitionIndex);
    child->setData(0, RoleType, "dir");
    child->setData(0, RolePath, f.fullPath);
    child->setData(0, RoleLoaded, false);
  }

  selectedTreeItem->setData(0, RoleLoaded, true);
  selectedTreeItem->setExpanded(true);
}

void MainWindow::onFileSelected() {
  const auto ranges = m_fileTable->selectedRanges();
  if (ranges.isEmpty()) return;
  const int row = ranges.first().topRow();
  if (row < 0 || row >= static_cast<int>(m_files.size())) return;

  const auto &f = m_files[row];
  auto dt = [](const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : "N/A"; };
  m_metadataPanel->setPlainText(QString("Path: %1\nInode: %2\nADS: %3\n\nSI Created: %4\nSI Modified: %5\nFN Created: %6\nFN Modified: %7")
                                    .arg(f.fullPath)
                                    .arg(f.inode)
                                    .arg(f.ntfs.hasAds ? f.ntfs.adsNames.join(';') : "none")
                                    .arg(dt(f.ntfs.standardInfo.created), dt(f.ntfs.standardInfo.modified),
                                         dt(f.ntfs.fileNameInfo.created), dt(f.ntfs.fileNameInfo.modified)));
}

void MainWindow::onExtractSelected() {
  if (!m_tskImage || m_selectedPartitionIndex < 0 || m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    QMessageBox::warning(this, "No partition", "Select a partition before extraction.");
    return;
  }

  const auto root = QFileDialog::getExistingDirectory(this, "Extraction destination");
  if (root.isEmpty()) return;

  domain::ExtractionTask task;
  task.image = m_imageInfo;
  task.partition = m_partitions[m_selectedPartitionIndex];
  task.settings.applyHostTimestamps = true;
  for (const auto &sel : m_fileTable->selectedRanges()) {
    for (int row = sel.topRow(); row <= sel.bottomRow(); ++row) {
      if (row >= 0 && row < static_cast<int>(m_files.size())) task.entries.push_back(m_files[row]);
    }
  }
  if (task.entries.empty() && !m_files.empty()) task.entries.push_back(m_files.front());
  task.destinationRoot = root;

  auto *thread = new QThread(this);
  auto *worker = new workers::ExtractionWorker(m_tskImage, task);
  worker->moveToThread(thread);

  connect(thread, &QThread::started, worker, &workers::ExtractionWorker::process);
  connect(worker, &workers::ExtractionWorker::completed, this,
          [this, thread, task](std::vector<domain::ExtractionResult> results, const QString &error) {
            setBusy(false);
            if (!error.isEmpty()) m_logManager.error(error);
            for (const auto &res : results) {
              m_catalog.push_back(utils::createCatalogRecord(task.image, task.partition, res));
            }
            thread->quit();
          });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);

  setBusy(true, "Extracting and hashing...");
  thread->start();
}

void MainWindow::onExportCatalog() {
  if (m_catalog.empty()) {
    QMessageBox::information(this, "No data", "No extraction records are available to export yet.");
    return;
  }

  const auto jsonPath = QFileDialog::getSaveFileName(this, "Export JSON catalog", {}, "JSON (*.json)");
  if (jsonPath.isEmpty()) return;
  QString error;
  if (!utils::MetadataSerializerJson::write(jsonPath, m_catalog, error)) {
    QMessageBox::warning(this, "Export failed", error);
    return;
  }
  const auto csvPath = QFileDialog::getSaveFileName(this, "Export CSV catalog", {}, "CSV (*.csv)");
  if (!csvPath.isEmpty() && !utils::MetadataSerializerCsv::write(csvPath, m_catalog, error)) {
    QMessageBox::warning(this, "CSV export failed", error);
  }
}

} // namespace fie::gui
