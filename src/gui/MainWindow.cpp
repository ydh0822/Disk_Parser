#include "ForensicImageExtractor/gui/MainWindow.h"
#include "ForensicImageExtractor/gui/CorrelationUtils.h"
#include "ForensicImageExtractor/gui/ArtifactDetailSession.h"
#include "ForensicImageExtractor/gui/ArtifactAnalysisSession.h"
#include "ForensicImageExtractor/gui/ArtifactDetailsText.h"
#include "ForensicImageExtractor/gui/NavigationUtils.h"

#include "ForensicImageExtractor/core/ImageReaderFactory.h"
#include "ForensicImageExtractor/cli/ArtifactTimelineJson.h"
#include "ForensicImageExtractor/utils/MetadataFactory.h"
#include "ForensicImageExtractor/utils/MetadataSerializerCsv.h"
#include "ForensicImageExtractor/utils/MetadataSerializerJson.h"
#include "ForensicImageExtractor/forensics/ArtifactTimelineService.h"
#include "ForensicImageExtractor/workers/ExtractionWorker.h"
#include "ForensicImageExtractor/workers/ForensicsWorkers.h"
#include "ForensicImageExtractor/forensics/FileSystemBrowser.h"
#include "ForensicImageExtractor/forensics/FileSystemHandle.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QDockWidget>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFontDatabase>
#include <QHash>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMenu>
#include <QFile>
#include <QMessageBox>
#include <QMetaType>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressBar>
#include <QSignalBlocker>
#include <QSet>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QTabWidget>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
#include <QTableView>
#include <QTextEdit>
#include <QThread>
#include <memory>
#include <array>
#include <algorithm>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QVector>

#if defined(FIE_HAS_TSK)
#include <tsk/libtsk.h>
#endif

namespace fie::gui {
namespace {
constexpr int RolePartition = Qt::UserRole;
constexpr int RoleType = Qt::UserRole + 1;
constexpr int RolePath = Qt::UserRole + 2;
constexpr int RoleLoaded = Qt::UserRole + 3;
constexpr int kPreviewBytesLimit = 256;

QString detectSignatureHint(const QByteArray &bytes) {
  if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') return "PE/EXE (MZ)";
  if (bytes.size() >= 4 && bytes[0] == '%' && bytes[1] == 'P' && bytes[2] == 'D' && bytes[3] == 'F') return "PDF";
  if (bytes.size() >= 4 && static_cast<unsigned char>(bytes[0]) == 0x50 && static_cast<unsigned char>(bytes[1]) == 0x4B &&
      static_cast<unsigned char>(bytes[2]) == 0x03 && static_cast<unsigned char>(bytes[3]) == 0x04) return "ZIP/OOXML/JAR";
  if (bytes.size() >= 4 && static_cast<unsigned char>(bytes[0]) == 0x7F && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') return "ELF";
  if (bytes.size() >= 8 && static_cast<unsigned char>(bytes[0]) == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G') return "PNG";
  if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xFF && static_cast<unsigned char>(bytes[1]) == 0xD8 &&
      static_cast<unsigned char>(bytes[2]) == 0xFF) return "JPEG";
  return "Unknown";
}

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
  for (int base = 0; base < bytes.size(); base += 16) {
    out += QString("%1  ").arg(base, 8, 16, QLatin1Char('0')).toUpper();
    QString ascii;
    for (int i = 0; i < 16; ++i) {
      const int idx = base + i;
      if (idx < bytes.size()) {
        const auto v = static_cast<unsigned char>(bytes[idx]);
        out += QString("%1 ").arg(v, 2, 16, QLatin1Char('0')).toUpper();
        ascii += (v >= 32 && v < 127) ? QChar(static_cast<char>(v)) : QChar('.');
      } else {
        out += "   ";
        ascii += ' ';
      }
    }
    out += QString(" |%1|\n").arg(ascii);
  }
  return out.trimmed();
}

QString backendLabel(fie::domain::ForensicBackend backend) {
  switch (backend) {
  case fie::domain::ForensicBackend::ReaderBridge:
    return "ReaderBridge";
  case fie::domain::ForensicBackend::PathFallback:
    return "PathFallback";
  case fie::domain::ForensicBackend::Unknown:
    return "Unknown";
  case fie::domain::ForensicBackend::NotApplicable:
  default:
    return "N/A";
  }
}

void logOperationResult(fie::utils::LogManager &log, const fie::domain::ForensicOperationResult &result,
                        const QString &context) {
  const QString base = QString("%1 [%2] reason=%3 msg=%4")
                           .arg(context,
                                backendLabel(result.backend),
                                result.diagnostic.reason,
                                result.diagnostic.userMessage);
  if (result.state == fie::domain::ForensicOperationState::Failure) {
    log.error(base);
  } else {
    log.info(base + (result.diagnostic.detail.isEmpty() ? "" : QString(" detail=%1").arg(result.diagnostic.detail)));
  }
}


QString correlationContextLine(const QString &filePath, const QString &artifactPath) {
  const auto correlation = pathCorrelation(filePath, artifactPath);
  if (!correlation.correlated()) {
    return QString("%1 [No direct path correlation]").arg(filePath);
  }
  return QString("%1 [%2]").arg(filePath, pathCorrelationTypeLabel(correlation.type));
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
  qRegisterMetaType<fie::domain::ForensicOperationResult>("fie::domain::ForensicOperationResult");
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
  m_currentPathValue = new QLabel("/");
  m_fsTypeValue = new QLabel("-");
  m_supportScopeValue = new QLabel("-");
  m_supportScopeValue->setWordWrap(true);
  summaryForm->addRow("Image Path", m_imagePathValue);
  summaryForm->addRow("Format", m_imageFormatValue);
  summaryForm->addRow("Image Size", m_imageSizeValue);
  summaryForm->addRow("Part", m_partitionValue);
  summaryForm->addRow("Path", m_currentPathValue);
  summaryForm->addRow("FS", m_fsTypeValue);
  summaryForm->addRow("Targets", m_supportScopeValue);

  auto *filterBox = new QGroupBox("Triage Filters", rootWidget);
  auto *filterLayout = new QVBoxLayout(filterBox);
  auto *quickGrid = new QGridLayout();
  quickGrid->setHorizontalSpacing(6);
  quickGrid->setVerticalSpacing(4);
  m_nameFilterEdit = new QLineEdit(filterBox);
  m_nameFilterEdit->setPlaceholderText("name contains");
  m_extensionFilterEdit = new QLineEdit(filterBox);
  m_extensionFilterEdit->setPlaceholderText("ext (exe or .exe)");
  m_pathFilterEdit = new QLineEdit(filterBox);
  m_pathFilterEdit->setPlaceholderText("path contains");
  m_statusFilterEdit = new QLineEdit(filterBox);
  m_statusFilterEdit->setPlaceholderText("status contains");
  m_typeFilterCombo = new QComboBox(filterBox);
  m_typeFilterCombo->addItems({"All entries", "Files only", "Directories only"});
  m_columnProfileCombo = new QComboBox(filterBox);
  m_columnProfileCombo->addItems({"Triage", "NTFS detail", "Extraction/status"});
  auto *clearFiltersButton = new QPushButton("Clear", filterBox);

  quickGrid->addWidget(new QLabel("Name", filterBox), 0, 0);
  quickGrid->addWidget(m_nameFilterEdit, 0, 1);
  quickGrid->addWidget(new QLabel("Ext", filterBox), 0, 2);
  quickGrid->addWidget(m_extensionFilterEdit, 0, 3);
  quickGrid->addWidget(new QLabel("Type", filterBox), 0, 4);
  quickGrid->addWidget(m_typeFilterCombo, 0, 5);
  quickGrid->addWidget(new QLabel("Columns", filterBox), 0, 6);
  quickGrid->addWidget(m_columnProfileCombo, 0, 7);
  quickGrid->addWidget(clearFiltersButton, 0, 8);

  quickGrid->addWidget(new QLabel("Path", filterBox), 1, 0);
  quickGrid->addWidget(m_pathFilterEdit, 1, 1, 1, 3);
  quickGrid->addWidget(new QLabel("Status", filterBox), 1, 4);
  quickGrid->addWidget(m_statusFilterEdit, 1, 5, 1, 2);

  auto *stateRow = new QHBoxLayout();
  m_deletedOnlyCheck = new QCheckBox("Deleted", filterBox);
  m_allocatedOnlyCheck = new QCheckBox("Allocated", filterBox);
  m_adsOnlyCheck = new QCheckBox("ADS (NTFS)", filterBox);
  stateRow->addWidget(m_deletedOnlyCheck);
  stateRow->addWidget(m_allocatedOnlyCheck);
  stateRow->addWidget(m_adsOnlyCheck);
  stateRow->addStretch(1);

  filterLayout->addLayout(quickGrid);
  filterLayout->addLayout(stateRow);
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

  m_centerTabs = new QTabWidget(mainSplitter);
  m_fileTable = new QTableView(m_centerTabs);
  m_fileTable->setModel(m_fileProxy);
  m_fileTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_fileTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_fileTable->setSortingEnabled(true);
  m_fileTable->setAlternatingRowColors(true);
  m_fileTable->setWordWrap(false);
  m_fileTable->verticalHeader()->setVisible(false);
  m_fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
  m_fileTable->horizontalHeader()->setStretchLastSection(true);
  m_fileTable->setColumnWidth(FileEntryTableModel::Name, 260);
  m_fileTable->setColumnWidth(FileEntryTableModel::Extension, 70);
  m_fileTable->setColumnWidth(FileEntryTableModel::LogicalPath, 420);
  m_fileTable->setColumnWidth(FileEntryTableModel::Size, 110);
  m_fileTable->setColumnWidth(FileEntryTableModel::Modified, 165);
  m_fileTable->setColumnWidth(FileEntryTableModel::FileId, 110);
  applyColumnProfile(0);

  auto *artifactTab = new QWidget(m_centerTabs);
  auto *artifactLayout = new QVBoxLayout(artifactTab);
  auto *artifactButtons = new QWidget(artifactTab);
  auto *artifactButtonsLayout = new QHBoxLayout(artifactButtons);
  auto *scanArtifactsButton = new QPushButton("Refresh / Re-scan", artifactButtons);
  m_analyzeArtifactsButton = new QPushButton("Analyze Artifacts", artifactButtons);
  auto *extractArtifactButton = new QPushButton("Extract selected", artifactButtons);
  auto *jumpArtifactButton = new QPushButton("Jump to file system", artifactButtons);
  auto *copyArtifactPathButton = new QPushButton("Copy logical path", artifactButtons);
  artifactButtonsLayout->addWidget(scanArtifactsButton);
  artifactButtonsLayout->addWidget(m_analyzeArtifactsButton);
  artifactButtonsLayout->addWidget(extractArtifactButton);
  artifactButtonsLayout->addWidget(jumpArtifactButton);
  artifactButtonsLayout->addWidget(copyArtifactPathButton);
  artifactButtonsLayout->addStretch(1);
  artifactLayout->addWidget(artifactButtons);
  m_artifactModel = new ArtifactTableModel(this);
  m_artifactProxy = new ArtifactSortProxyModel(this);
  m_artifactProxy->setSourceModel(m_artifactModel);
  m_artifactTable = new QTableView(artifactTab);
  m_artifactTable->setModel(m_artifactProxy);
  m_artifactTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_artifactTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
  m_artifactTable->setSortingEnabled(true);
  m_artifactTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  artifactLayout->addWidget(m_artifactTable, 1);

  auto *timelineTab = new QWidget(m_centerTabs);
  auto *timelineLayout = new QVBoxLayout(timelineTab);
  auto *timelineButtons = new QWidget(timelineTab);
  auto *timelineButtonsLayout = new QHBoxLayout(timelineButtons);
  auto *exportTimelineJsonButton = new QPushButton("Export Timeline JSON", timelineButtons);
  auto *exportTimelineCsvButton = new QPushButton("Export Timeline CSV", timelineButtons);
  m_timelineSummaryLabel = new QLabel("Analysis summary | artifacts=0 analyzed=0 parsed=0 partial=0 failed=0 unsupported=0 | events=0 [none]", timelineButtons);
  m_timelineSummaryLabel->setWordWrap(true);
  timelineButtonsLayout->addWidget(exportTimelineJsonButton);
  timelineButtonsLayout->addWidget(exportTimelineCsvButton);
  timelineButtonsLayout->addWidget(m_timelineSummaryLabel, 1);
  timelineLayout->addWidget(timelineButtons);
  m_timelineModel = new QStandardItemModel(this);
  m_timelineModel->setHorizontalHeaderLabels(
      {"Timestamp", "Event Type", "Artifact", "Profile", "Source Path", "Parser", "Parse State", "Summary"});
  m_timelineTable = new QTableView(timelineTab);
  m_timelineTable->setModel(m_timelineModel);
  m_timelineTable->setSortingEnabled(true);
  m_timelineTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_timelineTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  m_timelineTable->horizontalHeader()->setStretchLastSection(true);
  timelineLayout->addWidget(m_timelineTable, 1);

  m_centerTabs->addTab(m_fileTable, "Files");
  m_centerTabs->addTab(artifactTab, "Artifacts");
  m_centerTabs->addTab(timelineTab, "Timeline");

  connect(scanArtifactsButton, &QPushButton::clicked, this, &MainWindow::onScanArtifacts);
  connect(m_analyzeArtifactsButton, &QPushButton::clicked, this, &MainWindow::onAnalyzeArtifacts);
  connect(extractArtifactButton, &QPushButton::clicked, this, &MainWindow::onArtifactExtractSelected);
  connect(jumpArtifactButton, &QPushButton::clicked, this, &MainWindow::onArtifactJumpToFileSystem);
  connect(copyArtifactPathButton, &QPushButton::clicked, this, &MainWindow::onArtifactCopyPath);
  connect(exportTimelineJsonButton, &QPushButton::clicked, this, &MainWindow::onExportTimelineJson);
  connect(exportTimelineCsvButton, &QPushButton::clicked, this, &MainWindow::onExportTimelineCsv);

  auto *rightPanel = new QWidget(mainSplitter);
  auto *rightLayout = new QVBoxLayout(rightPanel);
  m_metadataPanel = new QTextEdit(rightPanel);
  m_metadataPanel->setReadOnly(true);
  m_metadataPanel->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
  m_previewPanel = new QTextEdit(rightPanel);
  m_previewPanel->setReadOnly(true);
  m_previewPanel->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
  rightLayout->addWidget(new QLabel("Metadata Summary", rightPanel));
  rightLayout->addWidget(m_metadataPanel, 1);
  rightLayout->addWidget(new QLabel("Safe Preview (first bytes)", rightPanel));
  rightLayout->addWidget(m_previewPanel, 1);

  mainSplitter->addWidget(leftPanel);
  mainSplitter->addWidget(m_centerTabs);
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
  m_extractStatusModel->setHorizontalHeaderLabels({"Path", "Status", "Bytes", "Context"});
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
  connect(m_artifactTable->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::onArtifactSelectionChanged);
  connect(m_centerTabs, &QTabWidget::currentChanged, this, &MainWindow::onCenterTabChanged);
  connect(m_nameFilterEdit, &QLineEdit::textChanged, m_fileProxy, &FileEntryFilterProxyModel::setNameContains);
  connect(m_deletedOnlyCheck, &QCheckBox::toggled, m_fileProxy, &FileEntryFilterProxyModel::setDeletedOnly);
  connect(m_allocatedOnlyCheck, &QCheckBox::toggled, m_fileProxy, &FileEntryFilterProxyModel::setAllocatedOnly);
  connect(m_adsOnlyCheck, &QCheckBox::toggled, m_fileProxy, &FileEntryFilterProxyModel::setAdsOnly);
  connect(m_extensionFilterEdit, &QLineEdit::textChanged, m_fileProxy, &FileEntryFilterProxyModel::setExtensionFilter);
  connect(m_pathFilterEdit, &QLineEdit::textChanged, m_fileProxy, &FileEntryFilterProxyModel::setPathContains);
  connect(m_statusFilterEdit, &QLineEdit::textChanged, m_fileProxy, &FileEntryFilterProxyModel::setStatusContains);
  connect(m_typeFilterCombo, &QComboBox::currentIndexChanged, this, [this](int idx) {
    m_fileProxy->setFilesOnly(idx == 1);
    m_fileProxy->setDirectoriesOnly(idx == 2);
  });
  connect(m_columnProfileCombo, &QComboBox::currentIndexChanged, this, &MainWindow::applyColumnProfile);
  connect(clearFiltersButton, &QPushButton::clicked, this, [this]() {
    m_nameFilterEdit->clear();
    m_extensionFilterEdit->clear();
    m_pathFilterEdit->clear();
    m_statusFilterEdit->clear();
    m_typeFilterCombo->setCurrentIndex(0);
    m_deletedOnlyCheck->setChecked(false);
    m_allocatedOnlyCheck->setChecked(false);
    m_adsOnlyCheck->setChecked(false);
  });

  m_fileTable->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_fileTable, &QWidget::customContextMenuRequested, this, [this](const QPoint &pt) {
    QMenu menu(this);
    auto *extract = menu.addAction("Extract selected");
    auto *copyPath = menu.addAction("Copy logical path");
    auto *jumpParent = menu.addAction("Jump to parent directory");
    menu.addSeparator();
    auto *copyInode = menu.addAction("Copy inode/file ID");
    auto *relatedArtifact = menu.addAction("Find related artifact context");
    menu.addSeparator();
    auto *exportMeta = menu.addAction("Export row metadata (JSON)");
    auto *chosen = menu.exec(m_fileTable->viewport()->mapToGlobal(pt));
    if (!chosen) return;

    const auto rows = m_fileTable->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    const auto source = m_fileProxy->mapToSource(rows.first());
    const auto *entry = m_fileModel->entryAt(source.row());
    if (!entry) return;

    if (chosen == extract) {
      onExtractSelected();
    } else if (chosen == copyPath) {
      QApplication::clipboard()->setText(entry->fullPath);
    } else if (chosen == copyInode) {
      QApplication::clipboard()->setText(QString::number(entry->inode));
    } else if (chosen == jumpParent) {
      const auto parent = entry->fullPath.left(entry->fullPath.lastIndexOf('/'));
      loadDirectoryAtPath(parent.isEmpty() ? "/" : parent);
    } else if (chosen == relatedArtifact) {
      QString selectionSummary;
      if (selectBestArtifactForFilePath(entry->fullPath, &selectionSummary, true)) {
        statusBar()->showMessage(selectionSummary, 6000);
      } else {
        statusBar()->showMessage("No correlated artifact rows for selected file", 5000);
      }
    } else if (chosen == exportMeta) {
      const auto path = QFileDialog::getSaveFileName(this, "Export row metadata", {}, "JSON (*.json)");
      if (path.isEmpty()) return;
      QFile f(path);
      if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
      const QString payload = QString("{\n  \"path\": \"%1\",\n  \"inode\": %2,\n  \"size\": %3,\n  \"deleted\": %4,\n  \"allocated\": %5\n}\n")
                                  .arg(entry->fullPath)
                                  .arg(entry->inode)
                                  .arg(entry->sizeBytes)
                                  .arg(entry->isDeleted ? "true" : "false")
                                  .arg(entry->isAllocated ? "true" : "false");
      f.write(payload.toUtf8());
    }
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
    m_artifacts.clear();
    m_artifactModel->setArtifacts({});
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
  tb->addAction("Scan artifacts", this, &MainWindow::onScanArtifacts);
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

  m_supportScopeValue->setText(supportScopeSummary());
  m_supportScopeValue->setToolTip("Primary targets: RAW/DD, E01, NTFS, FAT32, exFAT, EXT3, EXT4. ReFS/XFS are not currently targeted.");
  m_currentPathValue->setText(m_currentLogicalPath.isEmpty() ? "/" : m_currentLogicalPath);

  if (m_selectedPartitionIndex >= 0 && m_selectedPartitionIndex < static_cast<int>(m_partitions.size())) {
    const auto &p = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
    m_partitionValue->setText(QString("%1 [%2]").arg(p.identifier, p.description));
    const QString fsType = p.fileSystemType.isEmpty() ? "Unknown" : p.fileSystemType;
    QString suffix;
    if (isPrimarySupportedFileSystem(fsType)) {
      suffix = " • primary target";
    } else if (isKnownUnsupportedOrUnconfirmedFileSystem(fsType)) {
      suffix = " • not currently targeted";
    } else {
      suffix = " • unconfirmed";
    }
    m_fsTypeValue->setText(fsType + suffix);
  } else {
    m_partitionValue->setText("-");
    m_fsTypeValue->setText("-");
  }
}

bool MainWindow::isPrimarySupportedFileSystem(const QString &fsType) const {
  const QString upper = fsType.toUpper();
  return upper.contains("NTFS") || upper.contains("FAT32") || upper.contains("EXFAT") ||
         upper.contains("EXT3") || upper.contains("EXT4");
}

bool MainWindow::isKnownUnsupportedOrUnconfirmedFileSystem(const QString &fsType) const {
  const QString upper = fsType.toUpper();
  return upper.contains("REFS") || upper.contains("XFS");
}

QString MainWindow::supportScopeSummary() const {
  return "RAW/DD, E01 • NTFS, FAT32, exFAT, EXT3, EXT4";
}

void MainWindow::applyColumnProfile(int profileIndex) {
  if (!m_fileTable) return;

  struct ColumnProfile {
    std::array<int, FileEntryTableModel::ColumnCount> orderedColumns;
    std::array<bool, FileEntryTableModel::ColumnCount> visible{};
    int sortColumn{FileEntryTableModel::Name};
    Qt::SortOrder sortOrder{Qt::AscendingOrder};
  };

  auto makeProfile = [](const std::array<int, FileEntryTableModel::ColumnCount> &order,
                        std::initializer_list<int> shown,
                        int sortColumn,
                        Qt::SortOrder sortOrder) {
    ColumnProfile profile;
    profile.orderedColumns = order;
    profile.sortColumn = sortColumn;
    profile.sortOrder = sortOrder;
    profile.visible.fill(false);
    for (const int col : shown) {
      if (col >= 0 && col < FileEntryTableModel::ColumnCount) profile.visible[static_cast<size_t>(col)] = true;
    }
    return profile;
  };

  const std::array<int, FileEntryTableModel::ColumnCount> triageOrder{
      FileEntryTableModel::Name,      FileEntryTableModel::Extension,   FileEntryTableModel::Deleted,
      FileEntryTableModel::Allocated, FileEntryTableModel::Size,        FileEntryTableModel::Modified,
      FileEntryTableModel::LogicalPath, FileEntryTableModel::FileId,    FileEntryTableModel::Status,
      FileEntryTableModel::Type,      FileEntryTableModel::Created,     FileEntryTableModel::EntryModified,
      FileEntryTableModel::Accessed,  FileEntryTableModel::NtfsSiCreated, FileEntryTableModel::NtfsSiModified,
      FileEntryTableModel::NtfsFnCreated, FileEntryTableModel::NtfsFnModified, FileEntryTableModel::Ads};

  const std::array<int, FileEntryTableModel::ColumnCount> ntfsOrder{
      FileEntryTableModel::Name,      FileEntryTableModel::Extension,   FileEntryTableModel::LogicalPath,
      FileEntryTableModel::FileId,    FileEntryTableModel::Size,        FileEntryTableModel::Created,
      FileEntryTableModel::Modified,  FileEntryTableModel::EntryModified, FileEntryTableModel::Accessed,
      FileEntryTableModel::NtfsSiCreated, FileEntryTableModel::NtfsSiModified, FileEntryTableModel::NtfsFnCreated,
      FileEntryTableModel::NtfsFnModified, FileEntryTableModel::Ads,     FileEntryTableModel::Deleted,
      FileEntryTableModel::Allocated, FileEntryTableModel::Status,      FileEntryTableModel::Type};

  const std::array<int, FileEntryTableModel::ColumnCount> extractionOrder{
      FileEntryTableModel::Name,      FileEntryTableModel::Status,      FileEntryTableModel::Deleted,
      FileEntryTableModel::Allocated, FileEntryTableModel::Size,        FileEntryTableModel::Modified,
      FileEntryTableModel::LogicalPath, FileEntryTableModel::FileId,    FileEntryTableModel::Extension,
      FileEntryTableModel::Type,      FileEntryTableModel::Created,     FileEntryTableModel::EntryModified,
      FileEntryTableModel::Accessed,  FileEntryTableModel::NtfsSiCreated, FileEntryTableModel::NtfsSiModified,
      FileEntryTableModel::NtfsFnCreated, FileEntryTableModel::NtfsFnModified, FileEntryTableModel::Ads};

  const auto triageProfile = makeProfile(
      triageOrder,
      {FileEntryTableModel::Name, FileEntryTableModel::Extension, FileEntryTableModel::Deleted,
       FileEntryTableModel::Allocated, FileEntryTableModel::Size, FileEntryTableModel::Modified,
       FileEntryTableModel::LogicalPath, FileEntryTableModel::FileId, FileEntryTableModel::Status},
      FileEntryTableModel::Modified,
      Qt::DescendingOrder);

  const auto ntfsProfile = makeProfile(
      ntfsOrder,
      {FileEntryTableModel::Name, FileEntryTableModel::Extension, FileEntryTableModel::LogicalPath,
       FileEntryTableModel::FileId, FileEntryTableModel::Size, FileEntryTableModel::Created,
       FileEntryTableModel::Modified, FileEntryTableModel::EntryModified, FileEntryTableModel::Accessed,
       FileEntryTableModel::NtfsSiCreated, FileEntryTableModel::NtfsSiModified, FileEntryTableModel::NtfsFnCreated,
       FileEntryTableModel::NtfsFnModified, FileEntryTableModel::Ads, FileEntryTableModel::Deleted,
       FileEntryTableModel::Allocated},
      FileEntryTableModel::NtfsSiModified,
      Qt::DescendingOrder);

  const auto extractionProfile = makeProfile(
      extractionOrder,
      {FileEntryTableModel::Name, FileEntryTableModel::Status, FileEntryTableModel::Deleted,
       FileEntryTableModel::Allocated, FileEntryTableModel::Size, FileEntryTableModel::Modified,
       FileEntryTableModel::LogicalPath, FileEntryTableModel::FileId, FileEntryTableModel::Extension},
      FileEntryTableModel::Status,
      Qt::AscendingOrder);

  const ColumnProfile &profile = (profileIndex == 1) ? ntfsProfile : ((profileIndex == 2) ? extractionProfile : triageProfile);

  for (int col = 0; col < FileEntryTableModel::ColumnCount; ++col) {
    m_fileTable->setColumnHidden(col, !profile.visible[static_cast<size_t>(col)]);
  }

  QHeaderView *header = m_fileTable->horizontalHeader();
  for (int targetVisual = 0; targetVisual < FileEntryTableModel::ColumnCount; ++targetVisual) {
    const int logicalColumn = profile.orderedColumns[static_cast<size_t>(targetVisual)];
    const int currentVisual = header->visualIndex(logicalColumn);
    if (currentVisual != targetVisual && currentVisual >= 0) {
      header->moveSection(currentVisual, targetVisual);
    }
  }

  m_fileTable->sortByColumn(profile.sortColumn, profile.sortOrder);
}


void MainWindow::onOpenImage() {
  if (m_cancelCurrentTask) m_cancelCurrentTask();
  cancelArtifactDetailTask();
  m_artifactAnalysisRunId = 0;
  m_activeArtifactAnalysisContext.clear();
  invalidateArtifactDetailCache();

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
  connect(worker, &workers::ImageOpenWorker::completed, this,
          [this, thread](domain::ImageInfo info, const domain::ForensicOperationResult &result) {
    setBusy(false);
    logOperationResult(m_logManager, result, "Image open");
    if (!result.succeeded()) {
      QMessageBox::critical(this, "Open image failed", result.diagnostic.userMessage);
    } else {
      m_imageInfo = info;
      refreshEvidenceSummary();

      auto *partThread = new QThread(this);
      auto *partWorker = new workers::PartitionScanWorker(m_tskImage);
      partWorker->moveToThread(partThread);
      QPointer<workers::PartitionScanWorker> partWorkerGuard(partWorker);
      m_cancelCurrentTask = [partWorkerGuard]() {
        if (partWorkerGuard) QMetaObject::invokeMethod(partWorkerGuard, "requestCancel", Qt::QueuedConnection);
      };

      connect(partThread, &QThread::started, partWorker, &workers::PartitionScanWorker::process);
      connect(partWorker, &workers::PartitionScanWorker::completed, this,
              [this, partThread](std::vector<domain::PartitionInfo> parts,
                                 const domain::ForensicOperationResult &scanResult) {
                setBusy(false);
                logOperationResult(m_logManager, scanResult, "Partition enumeration");
                if (!scanResult.succeeded() && !scanResult.diagnostic.userMessage.contains("cancel", Qt::CaseInsensitive)) {
                  QMessageBox::warning(this, "Partition scan", scanResult.diagnostic.userMessage);
                }
                m_partitions = scanResult.succeeded() ? std::move(parts) : std::vector<domain::PartitionInfo>{};
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
  if (m_cancelCurrentTask) m_cancelCurrentTask();
  cancelArtifactDetailTask();
  m_artifactAnalysisRunId = 0;
  m_activeArtifactAnalysisContext.clear();
  invalidateArtifactDetailCache();

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

  const auto &selectedPartition = m_partitions[static_cast<size_t>(index)];
  if (isKnownUnsupportedOrUnconfirmedFileSystem(selectedPartition.fileSystemType)) {
    const QString warningKey = QString("%1:%2").arg(selectedPartition.identifier, selectedPartition.fileSystemType);
    if (!m_warnedSupportScopePartitions.contains(warningKey)) {
      m_warnedSupportScopePartitions.insert(warningKey);
      const QString warning = QString("Scope notice: %1 is not a current support target; browsing uses generic TSK traversal.")
                                  .arg(selectedPartition.fileSystemType);
      statusBar()->showMessage(warning, 9000);
      m_logManager.info(warning);
    }
  }

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
          [this, thread, selectedGuard](std::vector<domain::FileEntry> entries,
                                        const domain::ForensicOperationResult &result) {
            setBusy(false);
            logOperationResult(m_logManager, result, "Directory listing");
            if (!result.succeeded() && !result.diagnostic.userMessage.contains("cancel", Qt::CaseInsensitive)) {
              QMessageBox::warning(this, "Directory listing", result.diagnostic.userMessage);
            } else if (result.hasWarning()) {
              statusBar()->showMessage(result.diagnostic.userMessage, 7000);
              if (!result.diagnostic.detail.isEmpty()) {
                m_logManager.info(QString("Directory listing warning detail: %1").arg(result.diagnostic.detail));
              }
            }
            const bool listingSucceeded = result.succeeded();
            m_files = listingSucceeded ? std::move(entries) : std::vector<domain::FileEntry>{};
            populateFiles(selectedGuard.data());
            const auto navDecision = pendingNavigationDecision(listingSucceeded, m_pendingFileSelectionPath, m_pendingNavigationContext);
            if (navDecision.attemptFileSelection) {
              selectFileRowByPath(m_pendingFileSelectionPath);
            } else if (navDecision.showCompletionMessage) {
              statusBar()->showMessage(QString("Jump complete from %1").arg(m_pendingNavigationContext), 6000);
            }
            if (navDecision.clearPendingState) {
              m_pendingFileSelectionPath.clear();
              m_pendingNavigationContext.clear();
            }
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

  out.resize(kPreviewBytesLimit);
  const auto got = tsk_fs_file_read(tskFile, 0, out.data(), static_cast<size_t>(kPreviewBytesLimit), TSK_FS_FILE_READ_FLAG_NONE);
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
  if (rows.isEmpty()) {
    const QString placeholder = tabMetadataEmptySelectionPlaceholder(m_centerTabs->currentIndex(), false, true);
    if (!placeholder.isEmpty()) m_metadataPanel->setPlainText(placeholder);
    return;
  }

  const QModelIndex source = m_fileProxy->mapToSource(rows.first());
  const auto *f = m_fileModel->entryAt(source.row());
  if (!f) return;

  auto dt = [](const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : "N/A"; };
  const auto &ntfs = f->metadata.ntfs;
  const QString fsType = (m_selectedPartitionIndex >= 0 && m_selectedPartitionIndex < static_cast<int>(m_partitions.size()))
                             ? m_partitions[static_cast<size_t>(m_selectedPartitionIndex)].fileSystemType
                             : QString("Unknown");
  const QString ntfsContext = ntfs ? "present" : "not present (non-NTFS or not exposed)";
  const QString stateLine = QString("Allocated: %1 | Deleted: %2")
                                .arg(f->isAllocated ? "yes" : "no")
                                .arg(f->isDeleted ? "yes" : "no");
  const QString rowStatus = m_fileModel->data(m_fileModel->index(source.row(), FileEntryTableModel::Status), Qt::DisplayRole).toString();
  int relatedArtifacts = 0;
  int bestCorrelationRank = 100;
  QString bestCorrelationReason = "none";
  QStringList relatedNames;
  for (int r = 0; r < m_artifactModel->rowCount(); ++r) {
    const auto *artifact = m_artifactModel->artifactAt(r);
    if (!artifact) continue;
    const auto correlation = pathCorrelation(f->fullPath, artifact->sourceLogicalPath);
    if (!correlation.correlated()) continue;
    ++relatedArtifacts;
    if (correlation.rank < bestCorrelationRank) {
      bestCorrelationRank = correlation.rank;
      bestCorrelationReason = pathCorrelationTypeLabel(correlation.type);
    }
    if (relatedNames.size() < 3) {
      relatedNames.push_back(QString("%1 [%2]").arg(artifact->artifactName, pathCorrelationTypeLabel(correlation.type)));
    }
  }
  const QString relatedSummary = relatedArtifacts == 0
                                     ? "none"
                                     : QString("count=%1 | best=%2 | examples=%3")
                                           .arg(relatedArtifacts)
                                           .arg(bestCorrelationReason)
                                           .arg(relatedNames.join(", "));
  selectBestArtifactForFilePath(f->fullPath, nullptr, false);

  m_metadataPanel->setPlainText(
      QString("[Core]\n"
              "Path         : %1\n"
              "Type         : %3\n"
              "Size         : %5 bytes\n"
              "State        : %6\n"
              "Status       : %18\n"
              "File ID/Inode: %4\n"
              "Name         : %2\n"
              "\n[Correlation]\n"
              "Related artifacts : %19\n"
              "\n[Timeline - Generic MACB]\n"
              "Modified     : %10\n"
              "Created      : %9\n"
              "Entry Mod    : %11\n"
              "Accessed     : %12\n"
              "\n[Filesystem Context]\n"
              "Filesystem   : %7\n"
              "NTFS fields  : %8\n"
              "ADS (NTFS)   : %17\n"
              "SI Modified  : %14\n"
              "SI Created   : %13\n"
              "FN Modified  : %16\n"
              "FN Created   : %15")
          .arg(f->fullPath)
          .arg(f->name)
          .arg(f->isDirectory ? "directory" : "file")
          .arg(f->inode)
          .arg(f->sizeBytes)
          .arg(stateLine)
          .arg(fsType)
          .arg(ntfsContext)
          .arg(dt(f->metadata.timestamps.created), dt(f->metadata.timestamps.modified),
               dt(f->metadata.timestamps.entryModified), dt(f->metadata.timestamps.accessed),
               ntfs ? dt(ntfs->standardInfo.created) : "N/A", ntfs ? dt(ntfs->standardInfo.modified) : "N/A",
               ntfs ? dt(ntfs->fileNameInfo.created) : "N/A", ntfs ? dt(ntfs->fileNameInfo.modified) : "N/A")
          .arg((ntfs && ntfs->hasAds) ? ntfs->adsNames.join(';') : "N/A")
          .arg(rowStatus)
          .arg(relatedSummary);


  if (f->isDirectory) {
    m_previewPanel->setPlainText("[Read-only bounded preview]\nState: directory entry (content preview not available)");
    return;
  }
  if (f->sizeBytes == 0) {
    m_previewPanel->setPlainText("[Read-only bounded preview]\nState: empty file (0 bytes)");
    return;
  }

  QString previewError;
  const QByteArray preview = readPreviewBytes(*f, previewError);
  if (!previewError.isEmpty()) {
    m_previewPanel->setPlainText(previewError);
    return;
  }
  if (preview.isEmpty()) {
    m_previewPanel->setPlainText("[Read-only bounded preview]\nState: backend-limited or unreadable preview");
    return;
  }
  const bool isTruncated = preview.size() >= kPreviewBytesLimit;
  const QString truncation = isTruncated ? "Yes (bounded preview)" : "No";
  const QString signatureHint = detectSignatureHint(preview);
  m_previewPanel->setPlainText(QString("[Read-only bounded preview]\nLimit: %1 bytes\nBytes returned: %2\nTruncated: %3\nSignature hint: %4\n\n[Hexdump]\n%5\n\n[Sanitized text]\n%6")
                                   .arg(kPreviewBytesLimit)
                                   .arg(preview.size())
                                   .arg(truncation)
                                   .arg(signatureHint)
                                   .arg(bytesToHex(preview), bytesToSafeText(preview)));
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
  task.settings = m_appSettings;

  const auto selectedRows = m_fileTable->selectionModel()->selectedRows();
  for (const auto &proxyIdx : selectedRows) {
    const QModelIndex source = m_fileProxy->mapToSource(proxyIdx);
    if (const auto *entry = m_fileModel->entryAt(source.row())) task.entries.push_back(*entry);
  }
  if (task.entries.empty() && !m_files.empty()) task.entries.push_back(m_files.front());
  task.destinationRoot = root;

  startExtractionTask(std::move(task));
}

void MainWindow::startExtractionTask(domain::ExtractionTask task) {
  if (task.entries.empty()) {
    QMessageBox::information(this, "Extraction", "No entries selected for extraction.");
    return;
  }

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
          [this, thread, task, statusRows](std::vector<domain::ExtractionResult> results,
                                           const domain::ForensicOperationResult &result) {
            setBusy(false);
            logOperationResult(m_logManager, result, "Extraction");

            if (result.diagnostic.reason == "cancelled") {
              for (auto it = statusRows->cbegin(); it != statusRows->cend(); ++it) {
                const int row = it.value();
                m_extractStatusModel->setItem(row, 1, new QStandardItem("cancelled"));
                m_extractStatusModel->setItem(row, 3, new QStandardItem("Task cancelled; extracted payload suppressed"));
              }
              m_extractSummaryLabel->setText("Summary: cancelled (partial on-disk output may exist)");
              thread->quit();
              return;
            }

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



void MainWindow::loadDirectoryAtPath(const QString &path) {
  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return;
  }

  m_currentLogicalPath = path;
  refreshEvidenceSummary();
  auto *thread = new QThread(this);
  auto *worker = new workers::DirectoryListWorker(m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)], m_currentLogicalPath);
  worker->moveToThread(thread);

  connect(thread, &QThread::started, worker, &workers::DirectoryListWorker::process);
  connect(worker, &workers::DirectoryListWorker::completed, this,
          [this, thread](std::vector<domain::FileEntry> entries,
                         const domain::ForensicOperationResult &result) {
            setBusy(false);
            logOperationResult(m_logManager, result, "Directory listing");
            if (!result.succeeded() && !result.diagnostic.userMessage.contains("cancel", Qt::CaseInsensitive)) {
              QMessageBox::warning(this, "Directory listing", result.diagnostic.userMessage);
            } else if (result.hasWarning()) {
              statusBar()->showMessage(result.diagnostic.userMessage, 7000);
              if (!result.diagnostic.detail.isEmpty()) {
                m_logManager.info(QString("Directory listing warning detail: %1").arg(result.diagnostic.detail));
              }
            }
            const bool listingSucceeded = result.succeeded();
            m_files = listingSucceeded ? std::move(entries) : std::vector<domain::FileEntry>{};
            m_fileModel->setEntries(m_files);
            const auto navDecision = pendingNavigationDecision(listingSucceeded, m_pendingFileSelectionPath, m_pendingNavigationContext);
            if (navDecision.attemptFileSelection) {
              const QString pendingPath = m_pendingFileSelectionPath;
              const bool selected = selectFileRowByPath(pendingPath);
              const bool existsInSourceModel = sourceModelContainsPath(pendingPath);
              switch (pendingSelectionOutcome(listingSucceeded, pendingPath, existsInSourceModel, selected)) {
              case PendingSelectionOutcome::HiddenByFilters:
                m_logManager.info(QString("Pending file selection hidden by active filters: %1").arg(pendingPath));
                statusBar()->showMessage(
                    QString("Located parent directory, but target file is hidden by active filters: %1").arg(pendingPath),
                    8000);
                break;
              case PendingSelectionOutcome::NotFoundInLoadedDirectory:
                m_logManager.info(QString("Pending file selection path not found in loaded directory: %1").arg(pendingPath));
                statusBar()->showMessage(
                    QString("Located parent directory, but target file was not found in loaded directory: %1").arg(pendingPath),
                    8000);
                break;
              case PendingSelectionOutcome::SelectedVisible:
                if (!m_pendingNavigationContext.isEmpty()) {
                  statusBar()->showMessage(QString("Jump complete from %1").arg(m_pendingNavigationContext), 6000);
                }
                break;
              case PendingSelectionOutcome::None:
              default:
                break;
              }
            } else if (navDecision.showCompletionMessage) {
              statusBar()->showMessage(QString("Jump complete from %1").arg(m_pendingNavigationContext), 6000);
            }
            if (navDecision.clearPendingState) {
              m_pendingFileSelectionPath.clear();
              m_pendingNavigationContext.clear();
            }
            m_centerTabs->setCurrentIndex(0);
            thread->quit();
          });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);

  setBusy(true, QString("Enumerating %1 ...").arg(m_currentLogicalPath));
  thread->start();
}

bool MainWindow::selectFileRowByPath(const QString &fullPath) {
  if (fullPath.isEmpty()) return false;
  for (int row = 0; row < m_fileModel->rowCount(); ++row) {
    const auto *entry = m_fileModel->entryAt(row);
    if (!entry) continue;
    if (entry->fullPath.compare(fullPath, Qt::CaseInsensitive) != 0) continue;
    const QModelIndex sourceIndex = m_fileModel->index(row, FileEntryTableModel::Name);
    const QModelIndex proxyIndex = m_fileProxy->mapFromSource(sourceIndex);
    if (!proxyIndex.isValid()) return false;
    m_centerTabs->setCurrentIndex(0);
    m_fileTable->clearSelection();
    m_fileTable->setCurrentIndex(proxyIndex);
    m_fileTable->selectRow(proxyIndex.row());
    m_fileTable->scrollTo(proxyIndex, QAbstractItemView::PositionAtCenter);
    m_fileTable->setFocus();
    return true;
  }
  return false;
}

bool MainWindow::sourceModelContainsPath(const QString &fullPath) const {
  if (fullPath.isEmpty()) return false;
  for (int row = 0; row < m_fileModel->rowCount(); ++row) {
    const auto *entry = m_fileModel->entryAt(row);
    if (!entry) continue;
    if (entry->fullPath.compare(fullPath, Qt::CaseInsensitive) == 0) return true;
  }
  return false;
}

bool MainWindow::selectBestArtifactForFilePath(const QString &filePath,
                                             QString *selectionSummary,
                                             bool activateArtifactTab) {
  int bestRow = -1;
  int bestRank = 100;
  PathCorrelationType bestType = PathCorrelationType::None;
  QString bestPath;
  QString bestName;
  for (int r = 0; r < m_artifactModel->rowCount(); ++r) {
    const auto *artifact = m_artifactModel->artifactAt(r);
    if (!artifact) continue;
    const auto correlation = pathCorrelation(filePath, artifact->sourceLogicalPath);
    if (!correlation.correlated()) continue;

    const bool betterRank = correlation.rank < bestRank;
    const bool sameRankBetterTiebreak =
        correlation.rank == bestRank &&
        (QString::compare(artifact->sourceLogicalPath, bestPath, Qt::CaseInsensitive) < 0 ||
         (QString::compare(artifact->sourceLogicalPath, bestPath, Qt::CaseInsensitive) == 0 &&
          QString::compare(artifact->artifactName, bestName, Qt::CaseInsensitive) < 0));
    if (betterRank || sameRankBetterTiebreak) {
      bestRank = correlation.rank;
      bestRow = r;
      bestType = correlation.type;
      bestPath = artifact->sourceLogicalPath;
      bestName = artifact->artifactName;
    }
  }

  if (bestRow < 0) {
    if (!activateArtifactTab && m_artifactTable && m_artifactTable->selectionModel()) {
      QSignalBlocker blocker(m_artifactTable->selectionModel());
      m_artifactTable->clearSelection();
    }
    return false;
  }
  const QModelIndex proxyRow = m_artifactProxy->mapFromSource(m_artifactModel->index(bestRow, 0));
  if (!proxyRow.isValid()) return false;

  if (activateArtifactTab) {
    m_centerTabs->setCurrentIndex(1);
    m_artifactTable->selectRow(proxyRow.row());
    m_artifactTable->scrollTo(proxyRow, QAbstractItemView::PositionAtCenter);
    m_artifactTable->setFocus();
  } else {
    QSignalBlocker blocker(m_artifactTable->selectionModel());
    m_artifactTable->selectRow(proxyRow.row());
  }

  if (selectionSummary) {
    const auto *best = m_artifactModel->artifactAt(bestRow);
    if (best) {
      *selectionSummary = QString("Related artifact selected (%1): %2")
                              .arg(pathCorrelationTypeLabel(bestType), best->sourceLogicalPath);
    }
  }
  return true;
}

std::optional<domain::FileEntry> MainWindow::resolveFileEntryByPath(const QString &fullPath) const {
  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return std::nullopt;
  }

  forensics::FileSystemHandle fs;
  QString fsError;
  if (!fs.open(*m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)], fsError)) {
    return std::nullopt;
  }

  forensics::FileSystemBrowser browser;
  const int slash = fullPath.lastIndexOf('/');
  const auto parent = slash > 0 ? fullPath.left(slash) : QString("/");
  const auto name = fullPath.mid(slash + 1);
  QString listError;
  const auto entries = browser.listDirectory(fs, parent, listError);
  if (!listError.isEmpty()) return std::nullopt;
  for (const auto &entry : entries) {
    if (entry.name.compare(name, Qt::CaseInsensitive) == 0) return entry;
  }
  return std::nullopt;
}

bool MainWindow::isLikelyWindowsPartition() const {
  if (m_selectedPartitionIndex < 0 || m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) return false;
  const auto &partition = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
  const auto fsType = partition.fileSystemType.toUpper();
  const bool windowsFsType = fsType.contains("NTFS") || fsType.contains("FAT") || fsType.contains("EXFAT");
  if (!m_tskImage || !m_tskImage->isOpen()) return windowsFsType;

  forensics::FileSystemHandle fs;
  QString fsError;
  if (!fs.open(*m_tskImage, partition, fsError)) return windowsFsType;

  forensics::FileSystemBrowser browser;
  QString listError;
  const auto windowsEntries = browser.listDirectory(fs, "/Windows", listError);
  if (!listError.isEmpty()) return windowsFsType;
  return windowsFsType || !windowsEntries.empty();
}

void MainWindow::onScanArtifacts() {
  if (m_cancelCurrentTask) m_cancelCurrentTask();
  cancelArtifactDetailTask();
  m_artifactAnalysisRunId = 0;
  m_activeArtifactAnalysisContext.clear();
  invalidateArtifactDetailCache();

  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    QMessageBox::information(this, "Artifacts", "Select a partition first.");
    return;
  }

  if (!isLikelyWindowsPartition()) {
    QMessageBox::information(this, "Artifacts",
                             "Selected partition does not appear to be a Windows filesystem. "
                             "Skipping resolver scan to avoid noisy false misses.");
    m_artifacts.clear();
    m_warnedSupportScopePartitions.clear();
    m_artifactModel->setArtifacts({});
    rebuildTimelineView();
    return;
  }

  auto *thread = new QThread(this);
  auto *worker = new workers::ArtifactScanWorker(m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)]);
  worker->moveToThread(thread);
  QPointer<workers::ArtifactScanWorker> workerGuard(worker);
  m_cancelCurrentTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };
  connect(thread, &QThread::started, worker, &workers::ArtifactScanWorker::process);
  connect(worker, &workers::ArtifactScanWorker::completed, this,
          [this, thread](std::vector<domain::ArtifactRecord> artifacts,
                         const domain::ForensicOperationResult &result) {
            setBusy(false);
            logOperationResult(m_logManager, result, "Artifact scan");
            if (!result.succeeded() && !result.diagnostic.userMessage.contains("cancel", Qt::CaseInsensitive)) {
              QMessageBox::warning(this, "Artifact scan", result.diagnostic.userMessage);
            }
            if (result.hasWarning() && !result.diagnostic.detail.isEmpty()) {
              m_logManager.info(QString("Artifact scan warning: %1").arg(result.diagnostic.detail));
            }
            m_artifacts = std::move(artifacts);
            m_artifactModel->setArtifacts(m_artifacts);
            rebuildTimelineView();
            m_centerTabs->setCurrentIndex(1);
            thread->quit();
          });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  setBusy(true, "Scanning known artifact locations...");
  thread->start();
}

QString MainWindow::analysisContextKey() const {
  if (m_selectedPartitionIndex < 0 || m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return {};
  }
  const auto &partition = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
  return QString("%1|%2").arg(partition.identifier.trimmed().toLower(), partition.fileSystemType.trimmed().toLower());
}

void MainWindow::onAnalyzeArtifacts() {
  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    QMessageBox::information(this, "Analyze Artifacts", "Select a partition and run artifact scan first.");
    return;
  }
  if (m_artifacts.empty()) {
    QMessageBox::information(this, "Analyze Artifacts", "No artifact rows available. Run artifact scan first.");
    return;
  }

  cancelArtifactDetailTask();
  const QString contextKey = analysisContextKey();
  auto *thread = new QThread(this);
  auto *worker = new workers::ArtifactAnalysisWorker(
      m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)], m_artifacts);
  worker->moveToThread(thread);
  QPointer<workers::ArtifactAnalysisWorker> workerGuard(worker);
  m_cancelCurrentTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };

  const quint64 runId = ++m_artifactAnalysisRunId;
  m_activeArtifactAnalysisContext = contextKey;
  connect(thread, &QThread::started, worker, &workers::ArtifactAnalysisWorker::process);
  connect(worker, &workers::ArtifactAnalysisWorker::progress, this,
          [this](int processed, int total, const QString &path) {
            statusBar()->showMessage(QString("Analyzing artifacts %1/%2: %3").arg(processed).arg(total).arg(path));
          });
  connect(worker, &workers::ArtifactAnalysisWorker::completed, this,
          [this, thread, runId](const QString &context,
                                std::vector<domain::ArtifactRecord> analyzedArtifacts,
                                const domain::ForensicOperationResult &result) {
            setBusy(false);
            const QString currentContext = analysisContextKey();
            if (!shouldApplyAnalysisResult(m_artifactAnalysisRunId, m_activeArtifactAnalysisContext, currentContext,
                                           runId, context)) {
              thread->quit();
              return;
            }

            if (!result.succeeded() && result.diagnostic.reason != "cancelled") {
              QMessageBox::warning(this, "Analyze Artifacts", result.diagnostic.userMessage);
            }

            for (const auto &artifact : analyzedArtifacts) {
              if (!shouldAnalyzeArtifact(artifact)) continue;
              m_artifactDetailCache.put(artifactDetailCacheKey(artifact), artifact.details);
            }
            rebuildTimelineView();
            if (m_centerTabs) m_centerTabs->setCurrentIndex(2);
            m_artifactAnalysisRunId = 0;
            m_activeArtifactAnalysisContext.clear();
            thread->quit();
          });

  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  setBusy(true, "Analyzing parser-backed artifact details...");
  thread->start();
}

void MainWindow::onExportTimelineJson() {
  if (m_timelineEvents.empty()) {
    QMessageBox::information(this, "Export Timeline", "No timeline events to export.");
    return;
  }
  const auto path = QFileDialog::getSaveFileName(this, "Export timeline JSON", {}, "JSON (*.json)");
  if (path.isEmpty()) return;
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    QMessageBox::warning(this, "Export Timeline", "Failed to open output file.");
    return;
  }
  const auto bytes = QJsonDocument(fie::cli::artifactEventsToJsonArray(m_timelineEvents)).toJson(QJsonDocument::Indented);
  file.write(bytes);
  statusBar()->showMessage(QString("Timeline JSON exported: %1").arg(path), 6000);
}

void MainWindow::onExportTimelineCsv() {
  if (m_timelineEvents.empty()) {
    QMessageBox::information(this, "Export Timeline", "No timeline events to export.");
    return;
  }
  const auto path = QFileDialog::getSaveFileName(this, "Export timeline CSV", {}, "CSV (*.csv)");
  if (path.isEmpty()) return;
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    QMessageBox::warning(this, "Export Timeline", "Failed to open output file.");
    return;
  }
  file.write(fie::cli::artifactEventsToCsv(m_timelineEvents).toUtf8());
  statusBar()->showMessage(QString("Timeline CSV exported: %1").arg(path), 6000);
}

void MainWindow::onArtifactSelectionChanged() {
  const auto artifact = selectedArtifact();
  if (!artifact.has_value()) {
    cancelArtifactDetailTask();
    const QString placeholder = tabMetadataEmptySelectionPlaceholder(m_centerTabs->currentIndex(), true, false);
    if (!placeholder.isEmpty()) {
      m_metadataPanel->setPlainText(placeholder);
    } else {
      m_metadataPanel->clear();
    }
    return;
  }
  const QString key = artifactDetailCacheKey(*artifact);
  const auto cached = m_artifactDetailCache.get(key);
  if (cached.has_value()) {
    ArtifactDetailPanelState panelState = ArtifactDetailPanelState::Unsupported;
    if (cached->has_value()) {
      switch (cached->value().state) {
      case domain::ArtifactParseState::Parsed: panelState = ArtifactDetailPanelState::Parsed; break;
      case domain::ArtifactParseState::Partial: panelState = ArtifactDetailPanelState::Partial; break;
      case domain::ArtifactParseState::Failed: panelState = ArtifactDetailPanelState::Failed; break;
      case domain::ArtifactParseState::Unsupported: panelState = ArtifactDetailPanelState::Unsupported; break;
      }
    }
    refreshArtifactMetadataPanel(*artifact, *cached, "Details source : session cache", panelState);
    return;
  }

  refreshArtifactMetadataPanel(*artifact, std::nullopt, "Details source : loading on-demand...",
                               ArtifactDetailPanelState::Loading);
  requestArtifactDetails(*artifact);
}

std::optional<domain::ArtifactRecord> MainWindow::selectedArtifact() const {
  const auto rows = m_artifactTable->selectionModel()->selectedRows();
  if (rows.isEmpty()) return std::nullopt;
  const QModelIndex source = m_artifactProxy->mapToSource(rows.first());
  const auto *artifact = m_artifactModel->artifactAt(source.row());
  if (!artifact) return std::nullopt;
  return *artifact;
}

void MainWindow::refreshArtifactMetadataPanel(const domain::ArtifactRecord &artifact,
                                              const std::optional<domain::ArtifactDetails> &details,
                                              const QString &detailStatusLine,
                                              ArtifactDetailPanelState panelState) {
  QString selectedFileContext = "none selected";
  const auto fileRows = m_fileTable->selectionModel()->selectedRows();
  if (!fileRows.isEmpty()) {
    const QModelIndex fileSource = m_fileProxy->mapToSource(fileRows.first());
    const auto *entry = m_fileModel->entryAt(fileSource.row());
    if (entry) {
      selectedFileContext = correlationContextLine(entry->fullPath, artifact.sourceLogicalPath);
    }
  }

  QString bestLoadedFileContext = "none in current directory";
  int bestRank = 100;
  QString bestPath;
  for (int row = 0; row < m_fileModel->rowCount(); ++row) {
    const auto *entry = m_fileModel->entryAt(row);
    if (!entry) continue;
    const auto correlation = pathCorrelation(entry->fullPath, artifact.sourceLogicalPath);
    if (!correlation.correlated()) continue;
    if (correlation.rank < bestRank ||
        (correlation.rank == bestRank && QString::compare(entry->fullPath, bestPath, Qt::CaseInsensitive) < 0)) {
      bestRank = correlation.rank;
      bestPath = entry->fullPath;
      bestLoadedFileContext = correlationContextLine(entry->fullPath, artifact.sourceLogicalPath);
    }
  }

  m_metadataPanel->setPlainText(QString("[Artifact]\n"
                                        "Name         : %1\n"
                                        "Category     : %2\n"
                                        "Profile      : %3\n"
                                        "Path         : %4\n"
                                        "Status       : %5\n"
                                        "Target type  : %6\n"
                                        "Detail state : %7\n"
                                        "\n[Correlation Context]\n"
                                        "Selected file: %8\n"
                                        "Best loaded  : %9\n"
                                        "\n[Notes]\n"
                                        "%10\n\n%11")
                                .arg(artifact.artifactName, artifact.category, artifact.profile,
                                     artifact.sourceLogicalPath, artifact.status,
                                     artifact.directoryTarget ? "directory" : "file",
                                     detailStatusLine,
                                     selectedFileContext, bestLoadedFileContext,
                                     artifact.notes.isEmpty() ? "-" : artifact.notes,
                                     formatArtifactDetailsText(details, panelState)));
}

void MainWindow::cancelArtifactDetailTask() {
  if (m_cancelArtifactDetailTask) m_cancelArtifactDetailTask();
  m_cancelArtifactDetailTask = {};
  m_artifactDetailRequestId = 0;
  m_activeArtifactDetailKey.clear();
}

void MainWindow::invalidateArtifactDetailCache() {
  m_artifactDetailCache.clear();
  rebuildTimelineView();
}

void MainWindow::requestArtifactDetails(const domain::ArtifactRecord &artifact) {
  cancelArtifactDetailTask();
  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return;
  }

  auto *thread = new QThread(this);
  auto *worker = new workers::ArtifactDetailWorker(
      m_tskImage, m_partitions[static_cast<size_t>(m_selectedPartitionIndex)], artifact);
  worker->moveToThread(thread);
  QPointer<workers::ArtifactDetailWorker> workerGuard(worker);

  const quint64 requestId = ++m_artifactDetailRequestId;
  const QString requestKey = artifactDetailCacheKey(artifact);
  m_activeArtifactDetailKey = requestKey;
  m_cancelArtifactDetailTask = [workerGuard]() {
    if (workerGuard) QMetaObject::invokeMethod(workerGuard, "requestCancel", Qt::QueuedConnection);
  };

  connect(thread, &QThread::started, worker, &workers::ArtifactDetailWorker::process);
  connect(worker, &workers::ArtifactDetailWorker::completed, this,
          [this, thread, requestId](const QString &cacheKey,
                                    const domain::ArtifactRecord &artifact,
                                    const domain::ForensicOperationResult &result) {
            const auto details = artifact.details;
            const auto current = selectedArtifact();
            const QString currentKey = current.has_value() ? artifactDetailCacheKey(*current) : QString();
            if (!shouldApplyArtifactDetailResult(m_artifactDetailRequestId, m_activeArtifactDetailKey, currentKey,
                                                 requestId, cacheKey)) {
              thread->quit();
              return;
            }

            m_artifactDetailCache.put(cacheKey, details);
            QString statusLine = "Details source : on-demand parser";
            ArtifactDetailPanelState panelState = ArtifactDetailPanelState::Unsupported;
            if (result.diagnostic.reason == "cancelled") {
              statusLine = "Details source : cancelled";
              panelState = ArtifactDetailPanelState::Loading;
            } else if (!result.succeeded()) {
              statusLine = "Details source : load failed";
              panelState = ArtifactDetailPanelState::Failed;
            } else if (!details.has_value()) {
              statusLine = "Details source : unsupported artifact type";
              panelState = ArtifactDetailPanelState::Unsupported;
            } else if (details->state == domain::ArtifactParseState::Failed) {
              statusLine = "Details source : parse failed";
              panelState = ArtifactDetailPanelState::Failed;
            } else if (details->state == domain::ArtifactParseState::Partial) {
              statusLine = "Details source : partial parse";
              panelState = ArtifactDetailPanelState::Partial;
            } else {
              panelState = ArtifactDetailPanelState::Parsed;
            }

            if (current.has_value()) {
              refreshArtifactMetadataPanel(*current, details, statusLine, panelState);
            }
            rebuildTimelineView();
            m_cancelArtifactDetailTask = {};
            m_artifactDetailRequestId = 0;
            m_activeArtifactDetailKey.clear();
            thread->quit();
          });
  connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  thread->start();
}

void MainWindow::rebuildTimelineView() {
  if (!m_timelineModel) return;
  m_timelineModel->removeRows(0, m_timelineModel->rowCount());

  std::vector<domain::ArtifactRecord> artifacts = m_artifacts;
  for (auto &artifact : artifacts) {
    const QString key = artifactDetailCacheKey(artifact);
    const auto cached = m_artifactDetailCache.get(key);
    if (!cached.has_value()) continue;
    artifact.details = *cached;
  }

  forensics::ArtifactTimelineService timelineService;
  m_timelineEvents = timelineService.buildEvents(artifacts);
  m_lastAnalysisSummary = buildAnalysisSummary(artifacts, m_timelineEvents);
  if (m_timelineSummaryLabel) {
    m_timelineSummaryLabel->setText(formatAnalysisSummary(m_lastAnalysisSummary));
  }

  for (const auto &event : m_timelineEvents) {
    const int row = m_timelineModel->rowCount();
    m_timelineModel->insertRow(row);
    m_timelineModel->setItem(row, 0, new QStandardItem(event.timestamp ? event.timestamp->toString(Qt::ISODate) : "(untimed)"));
    m_timelineModel->setItem(row, 1, new QStandardItem(event.eventType));
    m_timelineModel->setItem(row, 2, new QStandardItem(event.artifactName));
    m_timelineModel->setItem(row, 3, new QStandardItem(event.profile));
    m_timelineModel->setItem(row, 4, new QStandardItem(event.sourceLogicalPath));
    m_timelineModel->setItem(row, 5, new QStandardItem(event.parserProvider));
    m_timelineModel->setItem(row, 6, new QStandardItem(artifactParseStateLabel(event.parseState)));
    m_timelineModel->setItem(row, 7, new QStandardItem(event.summary));
  }
}

void MainWindow::onCenterTabChanged(int index) {
  if (index == 1) {
    const auto rows = m_artifactTable->selectionModel()->selectedRows();
    if (!rows.isEmpty()) {
      m_artifactTable->scrollTo(rows.first(), QAbstractItemView::PositionAtCenter);
    }
    onArtifactSelectionChanged();
    return;
  }

  if (index == 0) {
    onFileSelected();
  }
}

void MainWindow::onArtifactJumpToFileSystem() {
  const auto rows = m_artifactTable->selectionModel()->selectedRows();
  if (rows.isEmpty()) return;
  const QModelIndex source = m_artifactProxy->mapToSource(rows.first());
  const auto *artifact = m_artifactModel->artifactAt(source.row());
  if (!artifact) return;

  m_pendingNavigationContext = QString("artifact '%1' (%2)").arg(artifact->artifactName, artifact->sourceLogicalPath);
  if (artifact->directoryTarget) {
    m_pendingFileSelectionPath.clear();
    loadDirectoryAtPath(artifact->sourceLogicalPath);
    return;
  }
  const int slash = artifact->sourceLogicalPath.lastIndexOf('/');
  const auto parent = slash > 0 ? artifact->sourceLogicalPath.left(slash) : QString("/");
  m_pendingFileSelectionPath = artifact->sourceLogicalPath;
  loadDirectoryAtPath(parent);
}

void MainWindow::onArtifactCopyPath() {
  const auto rows = m_artifactTable->selectionModel()->selectedRows();
  if (rows.isEmpty()) return;
  const QModelIndex source = m_artifactProxy->mapToSource(rows.first());
  const auto *artifact = m_artifactModel->artifactAt(source.row());
  if (!artifact) return;
  QApplication::clipboard()->setText(artifact->sourceLogicalPath);
}

void MainWindow::onArtifactExtractSelected() {
  if (!m_tskImage || !m_tskImage->isOpen() || m_selectedPartitionIndex < 0 ||
      m_selectedPartitionIndex >= static_cast<int>(m_partitions.size())) {
    return;
  }

  const auto rows = m_artifactTable->selectionModel()->selectedRows();
  if (rows.isEmpty()) {
    QMessageBox::information(this, "Artifacts", "Select one or more artifact rows to extract.");
    return;
  }

  domain::ExtractionTask task;
  task.image = m_imageInfo;
  task.partition = m_partitions[static_cast<size_t>(m_selectedPartitionIndex)];
  task.settings = m_appSettings;

  for (const auto &row : rows) {
    const QModelIndex sourceRow = m_artifactProxy->mapToSource(row);
    const auto *artifact = m_artifactModel->artifactAt(sourceRow.row());
    if (!artifact || artifact->status != "Present") continue;
    if (const auto entry = resolveFileEntryByPath(artifact->sourceLogicalPath)) {
      task.entries.push_back(*entry);
    }
  }

  if (task.entries.empty()) {
    QMessageBox::information(this, "Artifacts", "No present artifact files were selected.");
    return;
  }

  const auto root = QFileDialog::getExistingDirectory(this, "Select extraction destination");
  if (root.isEmpty()) return;
  task.destinationRoot = root;

  startExtractionTask(std::move(task));
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
