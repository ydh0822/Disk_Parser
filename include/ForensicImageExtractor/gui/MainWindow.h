#pragma once

#include "ForensicImageExtractor/core/IImageReader.h"
#include "ForensicImageExtractor/core/TskImageHandleAdapter.h"
#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/gui/FileEntryTableModel.h"
#include "ForensicImageExtractor/utils/LogManager.h"

#include <QMainWindow>
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

private:
  void setupUi();
  void setupMenu();
  void appendLog(const QString &line);
  void populatePartitions();
  void populateFiles(QTreeWidgetItem *selectedTreeItem);
  void setBusy(bool busy, const QString &message = {});
  void refreshEvidenceSummary();
  QByteArray readPreviewBytes(const domain::FileEntry &entry, QString &error) const;

  std::shared_ptr<core::IImageReader> m_reader;
  std::shared_ptr<core::TskImageHandleAdapter> m_tskImage;
  domain::ImageInfo m_imageInfo;
  std::vector<domain::PartitionInfo> m_partitions;
  std::vector<domain::FileEntry> m_files;
  std::vector<domain::CatalogRecord> m_catalog;
  int m_selectedPartitionIndex{-1};
  QString m_currentLogicalPath{"/"};

  utils::LogManager m_logManager;

  QTreeWidget *m_partitionTree{nullptr};
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
  QLabel *m_fsTypeValue{nullptr};

  QLineEdit *m_nameFilterEdit{nullptr};
  QCheckBox *m_deletedOnlyCheck{nullptr};
  QCheckBox *m_adsOnlyCheck{nullptr};
  QComboBox *m_typeFilterCombo{nullptr};

  QDockWidget *m_extractionDock{nullptr};
  QProgressBar *m_extractProgressBar{nullptr};
  QLabel *m_extractSummaryLabel{nullptr};
  QTableView *m_extractStatusView{nullptr};
  QStandardItemModel *m_extractStatusModel{nullptr};
};

} // namespace fie::gui
