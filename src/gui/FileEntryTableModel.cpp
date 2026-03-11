#include "ForensicImageExtractor/gui/FileEntryTableModel.h"

namespace fie::gui {
namespace {
QString dt(const std::optional<QDateTime> &v) { return v ? v->toString(Qt::ISODate) : ""; }
}

FileEntryTableModel::FileEntryTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int FileEntryTableModel::rowCount(const QModelIndex &parent) const {
  return parent.isValid() ? 0 : static_cast<int>(m_entries.size());
}

int FileEntryTableModel::columnCount(const QModelIndex &parent) const {
  return parent.isValid() ? 0 : ColumnCount;
}

QVariant FileEntryTableModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid() || index.row() < 0 || index.row() >= static_cast<int>(m_entries.size())) return {};
  const auto &f = m_entries[static_cast<size_t>(index.row())];
  const auto &ntfs = f.metadata.ntfs;

  if (role == Qt::DisplayRole) {
    switch (index.column()) {
    case Name: return f.name;
    case Type: return f.isDirectory ? "Directory" : "File";
    case Size: return QString::number(f.sizeBytes);
    case Deleted: return f.isDeleted ? "Yes" : "No";
    case FileId: return QString::number(f.inode);
    case Created: return dt(f.metadata.timestamps.created);
    case Modified: return dt(f.metadata.timestamps.modified);
    case EntryModified: return dt(f.metadata.timestamps.entryModified);
    case Accessed: return dt(f.metadata.timestamps.accessed);
    case NtfsSiCreated: return ntfs ? dt(ntfs->standardInfo.created) : "";
    case NtfsSiModified: return ntfs ? dt(ntfs->standardInfo.modified) : "";
    case NtfsFnCreated: return ntfs ? dt(ntfs->fileNameInfo.created) : "";
    case NtfsFnModified: return ntfs ? dt(ntfs->fileNameInfo.modified) : "";
    case Ads: return (ntfs && ntfs->hasAds) ? ntfs->adsNames.join(';') : "N/A";
    case Status: return m_status.value(index.row(), "Not started");
    default: return {};
    }
  }

  if (role == Qt::UserRole) {
    return f.fullPath;
  }

  return {};
}

QVariant FileEntryTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
  static const QStringList headers{"Name","Type","Size","Deleted","File ID/Inode","Created","Modified",
    "Entry Modified","Accessed","NTFS SI Created","NTFS SI Modified","NTFS FN Created","NTFS FN Modified",
    "ADS (NTFS)","Status"};
  return headers.value(section);
}

void FileEntryTableModel::setEntries(std::vector<domain::FileEntry> entries) {
  beginResetModel();
  m_entries = std::move(entries);
  m_status = QStringList(m_entries.size(), "Not started");
  endResetModel();
}

const domain::FileEntry *FileEntryTableModel::entryAt(int row) const {
  if (row < 0 || row >= static_cast<int>(m_entries.size())) return nullptr;
  return &m_entries[static_cast<size_t>(row)];
}

void FileEntryTableModel::setStatusForPath(const QString &path, const QString &status) {
  for (int i = 0; i < static_cast<int>(m_entries.size()); ++i) {
    if (m_entries[static_cast<size_t>(i)].fullPath == path) {
      m_status[i] = status;
      emit dataChanged(index(i, Status), index(i, Status));
      break;
    }
  }
}

FileEntryFilterProxyModel::FileEntryFilterProxyModel(QObject *parent) : QSortFilterProxyModel(parent) {}

void FileEntryFilterProxyModel::setNameContains(QString v) { m_nameContains = std::move(v); invalidateFilter(); }
void FileEntryFilterProxyModel::setDeletedOnly(bool v) { m_deletedOnly = v; invalidateFilter(); }
void FileEntryFilterProxyModel::setFilesOnly(bool v) { m_filesOnly = v; if (v) m_directoriesOnly = false; invalidateFilter(); }
void FileEntryFilterProxyModel::setDirectoriesOnly(bool v) { m_directoriesOnly = v; if (v) m_filesOnly = false; invalidateFilter(); }
void FileEntryFilterProxyModel::setAdsOnly(bool v) { m_adsOnly = v; invalidateFilter(); }

bool FileEntryFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const {
  const auto *m = qobject_cast<const FileEntryTableModel *>(sourceModel());
  if (!m) return true;
  const auto *entry = m->entryAt(sourceRow);
  if (!entry) return false;

  if (!m_nameContains.isEmpty() && !entry->name.contains(m_nameContains, Qt::CaseInsensitive)) return false;
  if (m_deletedOnly && !entry->isDeleted) return false;
  if (m_filesOnly && entry->isDirectory) return false;
  if (m_directoriesOnly && !entry->isDirectory) return false;
  if (m_adsOnly) {
    const bool hasAds = entry->metadata.ntfs && entry->metadata.ntfs->hasAds;
    if (!hasAds) return false;
  }

  Q_UNUSED(sourceParent)
  return true;
}

} // namespace fie::gui
