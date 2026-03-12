#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

namespace fie::gui {

class FileEntryTableModel : public QAbstractTableModel {
  Q_OBJECT
public:
  enum Column {
    Name = 0,
    LogicalPath,
    Type,
    Size,
    Deleted,
    Allocated,
    FileId,
    Created,
    Modified,
    EntryModified,
    Accessed,
    NtfsSiCreated,
    NtfsSiModified,
    NtfsFnCreated,
    NtfsFnModified,
    Ads,
    Status,
    ColumnCount
  };

  explicit FileEntryTableModel(QObject *parent = nullptr);

  int rowCount(const QModelIndex &parent = {}) const override;
  int columnCount(const QModelIndex &parent = {}) const override;
  QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

  void setEntries(std::vector<domain::FileEntry> entries);
  const domain::FileEntry *entryAt(int row) const;
  void setStatusForPath(const QString &path, const QString &status);

private:
  std::vector<domain::FileEntry> m_entries;
  QStringList m_status;
};

class FileEntryFilterProxyModel : public QSortFilterProxyModel {
  Q_OBJECT
public:
  explicit FileEntryFilterProxyModel(QObject *parent = nullptr);

  void setNameContains(QString v);
  void setDeletedOnly(bool v);
  void setAllocatedOnly(bool v);
  void setFilesOnly(bool v);
  void setDirectoriesOnly(bool v);
  void setAdsOnly(bool v);
  void setExtensionFilter(QString extension);
  void setPathContains(QString pathContains);

protected:
  bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
  bool lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const override;

private:
  QString m_nameContains;
  bool m_deletedOnly{false};
  bool m_allocatedOnly{false};
  bool m_filesOnly{false};
  bool m_directoriesOnly{false};
  bool m_adsOnly{false};
  QString m_extensionFilter;
  QString m_pathContains;
};

} // namespace fie::gui
