#include "ForensicImageExtractor/gui/MainWindow.h"

#include "ForensicImageExtractor/core/ImageReaderFactory.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"
#include "ForensicImageExtractor/workers/ExtractionWorker.h"
#include "ForensicImageExtractor/workers/ForensicsWorkers.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDockWidget>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHash>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QMetaType>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressBar>
#include <QSet>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QTableView>
#include <QTextEdit>
#include <QThread>
#include <memory>
#include <algorithm>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::gui {
namespace {
constexpr int RolePartition = Qt::UserRole;
constexpr int RoleType = Qt::UserRole + 1;
constexpr int RolePath = Qt::UserRole + 2;
constexpr int RoleLoaded = Qt::UserRole + 3;

QString formatBytes(quint64 size) {
  constexpr double kb = 1024.0;
  constexpr double mb = kb * 1024.0;
  constexpr double gb = mb * 1024.0;
  if (size >= static_cast<quint64>(gb)) return QString::number(size / gb, 'f', 2) + " GiB";
  if (size >= static_cast<quint64>(mb)) return QString::number(size / mb, 'f', 2) + " MiB";
  if (size >= static_cast<quint64>(kb)) return QString::number(size / kb, 'f', 2) + " KiB";
  return QString::number(size) + " B";
}

QString bytesToHex(const QByteArray &bytes) {
  QString out;
  for (int i = 0; i < bytes.size(); ++i) {
    out += QString("%1 ").arg(static_cast<unsigned char>(bytes[i]), 2, 16, QLatin1Char('0')).toUpper();
    if ((i + 1) % 16 == 0) out += '\n';
  }
  return out.trimmed();
}

QString bytesToSafeText(const QByteArray &bytes) {
  QString out;
  out.reserve(bytes.size());
  for (char c : bytes) {
    const uchar uc = static_cast<uchar>(c);
    out.push_back((uc >= 32 && uc < 127) ? QChar(c) : QChar('.'));
  }
  return out;
}
} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  qRegisterMetaType<fie::forensics::ProgressInfo>("fie::forensics::ProgressInfo");
  setupUi();
  setupMenu();
  connect(&m_logManager, &utils::LogManager::logAdded, this, &MainWindow::appendLog);
}

void MainWindow::setupUi() {
  setWindowTitle("Forensic Image Extractor");
  resize(1700, 950);

  auto *rootWidget = new QWidget(this);
  auto *rootLayout = new QVBoxLayout(rootWidget);

  auto *summaryBox = new QGroupBox("Evidence Summary", rootWidget);
  auto *summaryForm = new QFormLayout(summaryBox);
  m_imagePathValue = new QLabel("-");
  m_imageFormatValue = new QLabel("-");
  m_imageSizeValue = new QLabel("-");
  m_partitionValue = new QLabel("-");
  m_fsTypeValue = new QLabel("-");
  summaryForm->addRow("Image Path", m_imagePathValue);
  summaryForm->addRow("Format", m_imageFormatValue);
  summaryForm->addRow("Image Size", m_imageSizeValue);
  summaryForm->addRow("Selected Partition", m_partitionValue);
  summaryForm->addRow("Filesystem Type", m_fsTypeValue);

  auto *filterBox = new QGroupBox("File Filters", rootWidget);
  auto *filterForm = new QFormLayout(filterBox);
  m_nameFilterEdit = new QLineEdit(filterBox);
  m_nameFilterEdit->setPlaceholderText("name contains...");
  m_deletedOnlyCheck = new QCheckBox("Deleted only", filterBox);
  m_adsOnlyCheck = new QCheckBox("ADS only", filterBox);
  m_typeFilterCombo = new QComboBox(filterBox);
  m_typeFilterCombo->addItems({"All", "Files only", "Directories only"});
  filterForm->addRow("Name", m_nameFilterEdit);
  filterForm->addRow("Type", m_typeFilterCombo);
  filterForm->addRow("", m_deletedOnlyCheck);
  filterForm->addRow("", m_adsOnlyCheck);

  auto *topSplitter = new QSplitter(Qt::Horizontal, rootWidget);
  topSplitter->addWidget(summaryBox);
  topSplitter->addWidget(filterBox);
  topSplitter->setStretchFactor(0, 2);
  topSplitter->setStretchFactor(1, 1);

  auto *mainSplitter = new QSplitter(Qt::Horizontal, rootWidget);
  auto *leftPanel = new QWidget(mainSplitter);
  auto *leftLayout = new QVBoxLayout(leftPanel);
  m_partitionTree = new QTreeWidget(leftPanel);
  m_partitionTree->setHeaderLabel("Partitions / Directories");
  leftLayout->addWidget(m_partitionTree);

  m_fileModel = new FileEntryTableModel(this);
  m_fileProxy = new FileEntryFilterProxyModel(this);
  m_fileProxy->setSourceModel(m_fileModel);

  m_fileTable = new QTableView(mainSplitter);
  m_fileTable->setModel(m_fileProxy);
  m_fileTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_fileTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_fileTable->setSortingEnabled(true);
  m_fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

  auto *rightPanel = new QWidget(mainSplitter);
  auto *rightLayout = new QVBoxLayout(rightPanel);
  m_metadataPanel = new QTextEdit(rightPanel);
  m_metadataPanel->setReadOnly(true);
  m_previewPanel = new QTextEdit(rightPanel);
  m_previewPanel->setReadOnly(true);
  rightLayout->addWidget(new QLabel("Metadata Summary", rightPanel));
  rightLayout->addWidget(m_metadataPanel, 1);
  rightLayout->addWidget(new QLabel("Safe Preview (first bytes)", rightPanel));
  rightLayout->addWidget(m_previewPanel, 1);

  mainSplitter->addWidget(leftPanel);
  mainSplitter->addWidget(m_fileTable);
  mainSplitter->addWidget(rightPanel);
  mainSplitter->setStretchFactor(0, 2);
  mainSplitter->setStretchFactor(1, 4);
  mainSplitter->setStretchFactor(2, 3);

  m_logPanel = new QPlainTextEdit(this);
  m_logPanel->setReadOnly(true);
  m_logPanel->setMaximumHeight(180);

  rootLayout->addWidget(topSplitter);
  rootLayout->addWidget(mainSplitter, 1);
  rootLayout->addWidget(m_logPanel);
  setCentralWidget(rootWidget);

  m_extractionDock = new QDockWidget("Extraction Progress", this);
  auto *dockBody = new QWidget(m_extractionDock);
  auto *dockLayout = new QVBoxLayout(dockBody);
  m_extractProgressBar = new QProgressBar(dockBody);
  m_extractSummaryLabel = new QLabel("No extraction started", dockBody);
  m_extractStatusModel = new QStandardItemModel(this);
  m_extractStatusModel->setHorizontalHeaderLabels({"Path", "Status", "Bytes", "Warning/Error"});
  m_extractStatusView = new QTableView(dockBody);
  m_extractStatusView->setModel(m_extractStatusModel);
  m_extractStatusView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  dockLayout->addWidget(m_extractProgressBar);
  dockLayout->addWidget(m_extractSummaryLabel);
  dockLayout->addWidget(m_extractStatusView, 1);
  m_extractionDock->setWidget(dockBody);
  addDockWidget(Qt::BottomDockWidgetArea, m_extractionDock);

  connect(m_partitionTree, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onPartitionSelected);
  connect(m_fileTable->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::onFileSelected);
  connect(m_nameFilterEdit, &QLineEdit::textChanged, m_fileProxy, &FileEntryFilterProxyModel::setNameContains);
  connect(m_deletedOnlyCheck, &QCheckBox::toggled, m_fileProxy, &FileEntryFilterProxyModel::setDeletedOnly);
  connect(m_adsOnlyCheck, &QCheckBox::toggled, m_fileProxy, &FileEntryFilterProxyModel::setAdsOnly);
  connect(m_typeFilterCombo, &QComboBox::currentIndexChanged, this, [this](int idx) {
    m_fileProxy->setFilesOnly(idx == 1);
    m_fileProxy->setDirectoriesOnly(idx == 2);
  });

  refreshEvidenceSummary();
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
    m_fileModel->setEntries({});
    m_extractStatusModel->removeRows(0, m_extractStatusModel->rowCount());
    refreshEvidenceSummary();
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
  connect(m_stopAction, &QAction::triggered, this, [this]() {
    if (m_cancelCurrentTask) {
      m_logManager.info("Cancellation requested");
      m_cancelCurrentTask();
    }
  });

  connect(openAction, &QAction::triggered, this, &MainWindow::onOpenImage);
}

void MainWindow::appendLog(const QString &line) { m_logPanel->appendPlainText(line); }

void MainWindow::setBusy(bool busy, const QString &message) {
  m_stopAction->setEnabled(busy && static_cast<bool>(m_cancelCurrentTask));
  statusBar()->showMessage(message.isEmpty() ? (busy ? "Working..." : "Ready") : message);
  if (!busy) {
    m_cancelCurrentTask = {};
  }
}

void MainWindow::refreshEvidenceSummary() {
  m_imagePathValue->setText(m_imageInfo.path.isEmpty() ? "-" : m_imageInfo.path);
  m_imageFormatValue->setText(m_imageInfo.format.isEmpty() ? "-" : m_imageInfo.format);
  m_imageSizeValue->setText(m_imageInfo.sizeBytes == 0 ? "-" : QString("%1 (%2)").arg(m_imageInfo.sizeBytes).arg(formatBytes(m_imageInfo.sizeBytes)));

  if (m_selectedPartitionIndex >= 0 && m_selectedPartitionIndex < static_cast<int>(m_partitions.size())) {
    const auto &p = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
    m_partitionValue->setText(QString("%1 [%2]").arg(p.identifier, p.description));
    m_fsTypeValue->setText(p.fileSystemType.isEmpty() ? "Unknown" : p.fileSystemType);
  } else {
    m_partitionValue->setText("-");
    m_fsTypeValue->setText("-");
  }
}

void MainWindow::onOpenImage() {
  const auto path = QFileDialog::getOpenFileName(this, "Open Forensic Image");
  if (path.isEmpty()) return;

  auto createdReader = core::ImageReaderFactory::create(path);
  m_reader = std::shared_ptr<core::IImageReader>(std::move(createdReader));
  m_tskImage = std::make_shared<core::TskImageHandleAdapter>(m_reader, false);

  auto *thread = new QThread(this);
  auto *worker = new workers::ImageOpenWorker(m_reader, path);
  worker->moveToThread(thread);
  QPointer<workers::ImageOpenWorker> workerGuard(worker);
  m_cancelCurrentTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };

  connect(thread, &QThread::started, worker, &workers::ImageOpenWorker::process);
  connect(worker, &workers::ImageOpenWorker::completed, this, [this, thread](bool ok, domain::ImageInfo info, const QString &error) {
    setBusy(false);
    if (!ok) {
      QMessageBox::critical(this, "Open image failed", error);
    } else {
      m_imageInfo = info;
      refreshEvidenceSummary();
      if (m_reader && !m_reader->lastWarning().isEmpty()) m_logManager.info(m_reader->lastWarning());

      auto *partThread = new QThread(this);
      auto *partWorker = new workers::PartitionScanWorker(m_tskImage);
      partWorker->moveToThread(partThread);
      QPointer<workers::PartitionScanWorker> partWorkerGuard(partWorker);
      m_cancelCurrentTask = [partWorkerGuard]() {
        if (partWorkerGuard) QMetaObject::invokeMethod(partWorkerGuard, "requestCancel", Qt::QueuedConnection);
      };

      connect(partThread, &QThread::started, partWorker, &workers::PartitionScanWorker::process);
      connect(partWorker, &workers::PartitionScanWorker::completed, this,
              [this, partThread](std::vector<domain::PartitionInfo> parts, const QString &scanError, const QString &scanWarning) {
                setBusy(false);
                if (!scanWarning.isEmpty()) m_logManager.info(scanWarning);
                if (!scanError.isEmpty()) m_logManager.error(scanError);
                m_partitions = std::move(parts);
                populatePartitions();
                refreshEvidenceSummary();
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
  refreshEvidenceSummary();

  auto *thread = new QThread(this);
  auto *worker = new workers::DirectoryListWorker(m_tskImage, m_partitions[index], m_currentLogicalPath);
  worker->moveToThread(thread);
  QPointer<QTreeWidgetItem> selectedGuard(selected);
  QPointer<workers::DirectoryListWorker> workerGuard(worker);
  m_cancelCurrentTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };

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
  m_fileModel->setEntries(m_files);

  if (!selectedTreeItem) return;
  const bool alreadyLoaded = selectedTreeItem->data(0, RoleLoaded).toBool();
  if (alreadyLoaded) return;

  QSet<QString> existingPaths;
  for (int i = 0; i < selectedTreeItem->childCount(); ++i) {
    existingPaths.insert(selectedTreeItem->child(i)->data(0, RolePath).toString());
  }

  for (const auto &f : m_files) {
    if (!f.isDirectory) continue;
    if (existingPaths.contains(f.fullPath)) continue;
    auto *child = new QTreeWidgetItem(selectedTreeItem, {f.name});
    child->setData(0, RolePartition, m_selectedPartitionIndex);
    child->setData(0, RoleType, "dir");
    child->setData(0, RolePath, f.fullPath);
    child->setData(0, RoleLoaded, false);
  }

  selectedTreeItem->setData(0, RoleLoaded, true);
  selectedTreeItem->setExpanded(true);
}

QByteArray MainWindow::readPreviewBytes(const domain::FileEntry &entry, QString &error) const {
  QByteArray out;
#if defined(FIE_HAS_TSK)
  if (!m_tskImage || !m_tskImage->isOpen() || entry.isDirectory || entry.inode == 0 ||
      m_selectedPartitionIndex < 0 || m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return out;
  }

  forensics::FileSystemHandle fs;
  if (!fs.open(*m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)], error)) return out;

  TSK_FS_FILE *tskFile = tsk_fs_file_open_meta(fs.fs(), nullptr, static_cast<TSK_INUM_T>(entry.inode));
  if (!tskFile) {
    error = QString("Preview open failed: %1").arg(tsk_error_get());
    return out;
  }

  constexpr size_t kPreviewBytes = 256;
  out.resize(static_cast<int>(kPreviewBytes));
  const auto got = tsk_fs_file_read(tskFile, 0, out.data(), kPreviewBytes, TSK_FS_FILE_READ_FLAG_NONE);
  tsk_fs_file_close(tskFile);
  if (got < 0) {
    error = QString("Preview read failed: %1").arg(tsk_error_get());
    out.clear();
    return out;
  }
  out.resize(static_cast<int>(got));
#else
  Q_UNUSED(entry)
  Q_UNUSED(error)
#endif
  return out;
}

void MainWindow::onFileSelected() {
  const auto rows = m_fileTable->selectionModel()->selectedRows();
  if (rows.isEmpty()) return;

  const QModelIndex source = m_fileProxy->mapToSource(rows.first());
  const auto *f = m_fileModel->entryAt(source.row());
  if (!f) return;

  auto dt = [](const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : "N/A"; };
  const auto &ntfs = f->metadata.ntfs;
  m_metadataPanel->setPlainText(QString("Path: %1\nFile ID/Inode: %2\nDeleted: %3\nDirectory: %4\nSize: %5\n"
                                        "\nCreated: %6\nModified: %7\nEntry Modified: %8\nAccessed: %9\n"
                                        "\nADS (NTFS only): %10")
                                  .arg(f->fullPath)
                                  .arg(f->inode)
                                  .arg(f->isDeleted ? "yes" : "no")
                                  .arg(f->isDirectory ? "yes" : "no")
                                  .arg(f->sizeBytes)
                                  .arg(dt(f->metadata.timestamps.created), dt(f->metadata.timestamps.modified),
                                       dt(f->metadata.timestamps.entryModified), dt(f->metadata.timestamps.accessed))
                                  .arg((ntfs && ntfs->hasAds) ? ntfs->adsNames.join(';') : "not available"));

  QString previewError;
  const QByteArray preview = readPreviewBytes(*f, previewError);
  if (!previewError.isEmpty()) {
    m_previewPanel->setPlainText(previewError);
    return;
  }
  if (preview.isEmpty()) {
    m_previewPanel->setPlainText("Preview unavailable (directory, empty file, or backend limitation).");
    return;
  }
  m_previewPanel->setPlainText(QString("HEX:\n%1\n\nTEXT:\n%2").arg(bytesToHex(preview), bytesToSafeText(preview)));
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
  task.partition = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
  task.settings.applyHostTimestamps = true;

  const auto selectedRows = m_fileTable->selectionModel()->selectedRows();
  for (const auto &proxyIdx : selectedRows) {
    const QModelIndex source = m_fileProxy->mapToSource(proxyIdx);
    if (const auto *entry = m_fileModel->entryAt(source.row())) task.entries.push_back(*entry);
  }
  if (task.entries.empty() && !m_files.empty()) task.entries.push_back(m_files.front());
  task.destinationRoot = root;

  m_extractStatusModel->removeRows(0, m_extractStatusModel->rowCount());
  m_extractProgressBar->setValue(0);
  m_extractSummaryLabel->setText("Extraction started");

  auto *thread = new QThread(this);
  auto *worker = new workers::ExtractionWorker(m_tskImage, task);
  worker->moveToThread(thread);
  QPointer<workers::ExtractionWorker> workerGuard(worker);
  m_cancelCurrentTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };

  auto statusRows = std::make_shared<QHash<QString, int>>();

  connect(thread, &QThread::started, worker, &workers::ExtractionWorker::process);
  connect(worker, &workers::ExtractionWorker::progress, this, [this, statusRows](const forensics::ProgressInfo &progress) {
    const int pct = progress.totalBytesEstimated == 0
                        ? 0
                        : static_cast<int>((100.0 * progress.totalBytesProcessed) / progress.totalBytesEstimated);
    m_extractProgressBar->setValue(std::clamp(pct, 0, 100));
    statusBar()->showMessage(QString("Extracting %1 (%2/%3 bytes)")
                                 .arg(progress.currentPath)
                                 .arg(progress.totalBytesProcessed)
                                 .arg(progress.totalBytesEstimated));
    m_fileModel->setStatusForPath(progress.currentPath, QString("Processing %1/%2")
                                                        .arg(progress.fileBytesProcessed)
                                                        .arg(progress.fileBytesTotal));

    if (!statusRows->contains(progress.currentPath)) {
      const int row = m_extractStatusModel->rowCount();
      m_extractStatusModel->insertRow(row);
      m_extractStatusModel->setItem(row, 0, new QStandardItem(progress.currentPath));
      m_extractStatusModel->setItem(row, 1, new QStandardItem("Processing"));
      m_extractStatusModel->setItem(row, 2, new QStandardItem(QString::number(progress.fileBytesProcessed)));
      m_extractStatusModel->setItem(row, 3, new QStandardItem(""));
      statusRows->insert(progress.currentPath, row);
    } else {
      const int row = statusRows->value(progress.currentPath);
      m_extractStatusModel->setItem(row, 2, new QStandardItem(QString::number(progress.fileBytesProcessed)));
    }
  });

  connect(worker, &workers::ExtractionWorker::completed, this,
          [this, thread, task, statusRows](std::vector<domain::ExtractionResult> results, const QString &error) {
            setBusy(false);
            if (!error.isEmpty()) m_logManager.error(error);

            int success = 0;
            int warning = 0;
            int failed = 0;
            int skipped = 0;

            for (const auto &res : results) {
              m_catalog.push_back(utils::createCatalogRecord(task.image, task.partition, res));
              m_fileModel->setStatusForPath(res.source.fullPath, res.status);

              const QString issue = !res.error.isEmpty() ? res.error : res.warning;
              int row = statusRows->value(res.source.fullPath, -1);
              if (row < 0) {
                row = m_extractStatusModel->rowCount();
                m_extractStatusModel->insertRow(row);
                m_extractStatusModel->setItem(row, 0, new QStandardItem(res.source.fullPath));
              }
              m_extractStatusModel->setItem(row, 1, new QStandardItem(res.status));
              m_extractStatusModel->setItem(row, 2, new QStandardItem(QString::number(res.bytesWritten)));
              m_extractStatusModel->setItem(row, 3, new QStandardItem(issue));

              if (res.status.contains("skip", Qt::CaseInsensitive)) {
                ++skipped;
              } else if (!res.error.isEmpty()) {
                ++failed;
              } else if (!res.warning.isEmpty()) {
                ++warning;
                ++success;
              } else {
                ++success;
              }
            }

            m_extractProgressBar->setValue(100);
            m_extractSummaryLabel->setText(QString("Summary: success=%1 warning=%2 error=%3 skipped=%4")
                                               .arg(success)
                                               .arg(warning)
                                               .arg(failed)
                                               .arg(skipped));
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
