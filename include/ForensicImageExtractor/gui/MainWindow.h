#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"
#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/gui/FileEntryTableModel.h"
#include "ForensicImageExtractor/gui/ArtifactTableModel.h"
#include "ForensicImageExtractor/utils/LogManager.h"

#include <QMainWindow>
#include <QSet>
#include <functional>
#include <memory>

class QAction;
class QCheckBox;
class QComboBox;
class QDockWidget;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QTableView;
class QStandardItemModel;
class QTabWidget;
class QTextEdit;
class QTreeWidget;
class QTreeWidgetItem;

namespace fie::gui {

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget *parent = nullptr);

private slots:
  void onOpenImage();
  void onPartitionSelected();
  void onFileSelected();
  void onExtractSelected();
  void onExportCatalog();
  void onScanArtifacts();
  void onArtifactSelectionChanged();
  void onArtifactExtractSelected();
  void onArtifactJumpToFileSystem();
  void onArtifactCopyPath();

private:
  void setupUi();
  void setupMenu();
  void appendLog(const QString &line);
  void populatePartitions();
  void populateFiles(QTreeWidgetItem *selectedTreeItem);
  void setBusy(bool busy, const QString &message = {});
  void refreshEvidenceSummary();
  QByteArray readPreviewBytes(const domain::FileEntry &entry, QString &error) const;
  void loadDirectoryAtPath(const QString &path);
  void startExtractionTask(domain::ExtractionTask task);
  std::optional<domain::FileEntry> resolveFileEntryByPath(const QString &fullPath) const;
  bool isLikelyWindowsPartition() const;
  bool selectFileRowByPath(const QString &fullPath);
  bool isPrimarySupportedFileSystem(const QString &fsType) const;
  bool isKnownUnsupportedOrUnconfirmedFileSystem(const QString &fsType) const;
  QString supportScopeSummary() const;
  void applyColumnProfile(int profileIndex);

  std::shared_ptr<core::IImageReader> m_reader;
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  domain::ImageInfo m_imageInfo;
  std::vector<domain::PartitionInfo> m_partitions;
  std::vector<domain::FileEntry> m_files;
  std::vector<domain::CatalogRecord> m_catalog;
  std::vector<domain::ArtifactRecord> m_artifacts;
  domain::AppSettings m_appSettings;
  int m_selectedPartitionIndex{-1};
  QString m_currentLogicalPath{"/"};

  utils::LogManager m_logManager;

  QTreeWidget *m_partitionTree{nullptr};
  QTabWidget *m_centerTabs{nullptr};
  QTableView *m_fileTable{nullptr};
  FileEntryTableModel *m_fileModel{nullptr};
  FileEntryFilterProxyModel *m_fileProxy{nullptr};
  QTextEdit *m_metadataPanel{nullptr};
  QTextEdit *m_previewPanel{nullptr};
  QPlainTextEdit *m_logPanel{nullptr};
  QAction *m_stopAction{nullptr};
  std::function<void()> m_cancelCurrentTask;

  QLabel *m_imagePathValue{nullptr};
  QLabel *m_imageFormatValue{nullptr};
  QLabel *m_imageSizeValue{nullptr};
  QLabel *m_partitionValue{nullptr};
  QLabel *m_currentPathValue{nullptr};
  QLabel *m_fsTypeValue{nullptr};
  QLabel *m_supportScopeValue{nullptr};

  QLineEdit *m_nameFilterEdit{nullptr};
  QCheckBox *m_deletedOnlyCheck{nullptr};
  QCheckBox *m_allocatedOnlyCheck{nullptr};
  QCheckBox *m_adsOnlyCheck{nullptr};
  QComboBox *m_typeFilterCombo{nullptr};
  QLineEdit *m_extensionFilterEdit{nullptr};
  QLineEdit *m_pathFilterEdit{nullptr};
  QLineEdit *m_statusFilterEdit{nullptr};
  QComboBox *m_columnProfileCombo{nullptr};

  QDockWidget *m_extractionDock{nullptr};
  QProgressBar *m_extractProgressBar{nullptr};
  QLabel *m_extractSummaryLabel{nullptr};
  QTableView *m_extractStatusView{nullptr};

  QTableView *m_artifactTable{nullptr};
  ArtifactTableModel *m_artifactModel{nullptr};
  ArtifactSortProxyModel *m_artifactProxy{nullptr};
  QStandardItemModel *m_extractStatusModel{nullptr};

  QSet<QString> m_warnedSupportScopePartitions;
  QString m_pendingFileSelectionPath;
};

} // namespace fie::gui
