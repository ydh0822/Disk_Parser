#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

namespace fie::gui {

class ArtifactTableModel : public QAbstractTableModel {
  Q_OBJECT
public:
  enum Column {
    Category = 0,
    Artifact,
    Profile,
    LogicalPath,
    Status,
    Size,
    Timestamp,
    Partition,
    Notes,
    ColumnCount
  };

  explicit ArtifactTableModel(QObject *parent = nullptr);

  int rowCount(const QModelIndex &parent = {}) const override;
  int columnCount(const QModelIndex &parent = {}) const override;
  QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

  void setArtifacts(std::vector<domain::ArtifactRecord> artifacts);
  const domain::ArtifactRecord *artifactAt(int row) const;

private:
  std::vector<domain::ArtifactRecord> m_artifacts;
};


class ArtifactSortProxyModel : public QSortFilterProxyModel {
  Q_OBJECT
public:
  explicit ArtifactSortProxyModel(QObject *parent = nullptr);

protected:
  bool lessThan(const QModelIndex &sourceLeft, const QModelIndex &sourceRight) const override;
};

} // namespace fie::gui
