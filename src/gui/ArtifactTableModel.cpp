#include "ForensicImageExtractor/gui/ArtifactTableModel.h"

namespace fie::gui {

ArtifactTableModel::ArtifactTableModel(QObject *parent) : QAbstractTableModel(parent) {}

int ArtifactTableModel::rowCount(const QModelIndex &parent) const {
  return parent.isValid() ? 0 : static_cast<int>(m_artifacts.size());
}

int ArtifactTableModel::columnCount(const QModelIndex &parent) const {
  return parent.isValid() ? 0 : ColumnCount;
}

QVariant ArtifactTableModel::data(const QModelIndex &index, int role) const {
  if (!index.isValid() || index.row() < 0 || index.row() >= static_cast<int>(m_artifacts.size())) return {};
  const auto &a = m_artifacts[static_cast<size_t>(index.row())];
  if (role == Qt::DisplayRole) {
    switch (index.column()) {
    case Category: return a.category;
    case Artifact: return a.artifactName;
    case Profile: return a.profile;
    case LogicalPath: return a.sourceLogicalPath;
    case Status: return a.directoryTarget ? QString("%1 (Directory)").arg(a.status) : a.status;
    case Size: return a.sizeBytes == 0 ? QString() : QString::number(a.sizeBytes);
    case Timestamp: return a.keyTimestamp ? a.keyTimestamp->toString(Qt::ISODate) : QString();
    case Partition: return a.partitionIdentifier;
    case Notes: return a.directoryTarget ? (a.notes.isEmpty() ? QString("Directory target") : QString("[Directory] %1").arg(a.notes)) : a.notes;
    default: return {};
    }
  }
  return {};
}

QVariant ArtifactTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
  if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
  static const QStringList headers{"Category", "Artifact", "Profile", "Logical Path", "Status", "Size", "Key Timestamp",
                                   "Partition", "Notes"};
  return headers.value(section);
}

void ArtifactTableModel::setArtifacts(std::vector<domain::ArtifactRecord> artifacts) {
  beginResetModel();
  m_artifacts = std::move(artifacts);
  endResetModel();
}

const domain::ArtifactRecord *ArtifactTableModel::artifactAt(int row) const {
  if (row < 0 || row >= static_cast<int>(m_artifacts.size())) return nullptr;
  return &m_artifacts[static_cast<size_t>(row)];
}


ArtifactSortProxyModel::ArtifactSortProxyModel(QObject *parent) : QSortFilterProxyModel(parent) {}

bool ArtifactSortProxyModel::lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const {
  const auto *m = qobject_cast<const ArtifactTableModel *>(sourceModel());
  if (!m) return QSortFilterProxyModel::lessThan(sourceLeft, sourceRight);
  const auto *left = m->artifactAt(sourceLeft.row());
  const auto *right = m->artifactAt(sourceRight.row());
  if (!left || !right) return QSortFilterProxyModel::lessThan(sourceLeft, sourceRight);

  switch (sourceLeft.column()) {
  case ArtifactTableModel::Size:
    return left->sizeBytes < right->sizeBytes;
  case ArtifactTableModel::Timestamp:
    return left->keyTimestamp.value_or(QDateTime()) < right->keyTimestamp.value_or(QDateTime());
  default:
    break;
  }

  return QSortFilterProxyModel::lessThan(sourceLeft, sourceRight);
}

} // namespace fie::gui
