#include "ForensicImageExtractor/gui/ArtifactTableModel.h"
#include "ForensicImageExtractor/gui/CorrelationUtils.h"

#include <QItemSelectionModel>
#include <QObject>
#include <QSignalBlocker>

int runArtifactCorrelationFlowTests() {
  fie::gui::ArtifactTableModel artifactModel;
  fie::gui::ArtifactSortProxyModel artifactProxy;
  artifactProxy.setSourceModel(&artifactModel);

  fie::domain::ArtifactRecord exactA;
  exactA.artifactName = "A Exact";
  exactA.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";

  fie::domain::ArtifactRecord exactB;
  exactB.artifactName = "B Exact";
  exactB.sourceLogicalPath = "/Users/Alice/NTUSER.DAT";

  fie::domain::ArtifactRecord ancestor;
  ancestor.artifactName = "Ancestor";
  ancestor.sourceLogicalPath = "/Users/Alice";

  fie::domain::ArtifactRecord descendant;
  descendant.artifactName = "Descendant";
  descendant.sourceLogicalPath = "/Users/Alice/NTUSER.DAT.LOG1";

  artifactModel.setArtifacts({descendant, ancestor, exactB, exactA});

  const QString filePath = "/Users/Alice/NTUSER.DAT";
  int bestRow = -1;
  int bestRank = 100;
  QString bestPath;
  QString bestName;

  for (int row = 0; row < artifactModel.rowCount(); ++row) {
    const auto *artifact = artifactModel.artifactAt(row);
    if (!artifact) continue;
    const auto correlation = fie::gui::pathCorrelation(filePath, artifact->sourceLogicalPath);
    if (!correlation.correlated()) continue;

    const bool betterRank = correlation.rank < bestRank;
    const bool sameRankBetterTiebreak =
        correlation.rank == bestRank &&
        (QString::compare(artifact->sourceLogicalPath, bestPath, Qt::CaseInsensitive) < 0 ||
         (QString::compare(artifact->sourceLogicalPath, bestPath, Qt::CaseInsensitive) == 0 &&
          QString::compare(artifact->artifactName, bestName, Qt::CaseInsensitive) < 0));
    if (betterRank || sameRankBetterTiebreak) {
      bestRow = row;
      bestRank = correlation.rank;
      bestPath = artifact->sourceLogicalPath;
      bestName = artifact->artifactName;
    }
  }

  if (bestRow < 0) return 1;
  if (bestRank != 0) return 1;

  const auto *best = artifactModel.artifactAt(bestRow);
  if (!best) return 1;
  if (best->artifactName != "A Exact") return 1;

  const QModelIndex proxyIndex = artifactProxy.mapFromSource(artifactModel.index(bestRow, 0));
  if (!proxyIndex.isValid()) return 1;

  QItemSelectionModel selectionModel(&artifactProxy);
  int silentSignalCount = 0;
  QObject::connect(&selectionModel, &QItemSelectionModel::selectionChanged,
                   [&silentSignalCount](const QItemSelection &, const QItemSelection &) { ++silentSignalCount; });


  auto passiveSyncSelection = [&artifactModel, &artifactProxy, &selectionModel](const QString &candidatePath) {
    int chosenRow = -1;
    int chosenRank = 100;
    QString chosenPath;
    QString chosenName;

    for (int row = 0; row < artifactModel.rowCount(); ++row) {
      const auto *artifact = artifactModel.artifactAt(row);
      if (!artifact) continue;
      const auto correlation = fie::gui::pathCorrelation(candidatePath, artifact->sourceLogicalPath);
      if (!correlation.correlated()) continue;

      const bool betterRank = correlation.rank < chosenRank;
      const bool sameRankBetterTiebreak =
          correlation.rank == chosenRank &&
          (QString::compare(artifact->sourceLogicalPath, chosenPath, Qt::CaseInsensitive) < 0 ||
           (QString::compare(artifact->sourceLogicalPath, chosenPath, Qt::CaseInsensitive) == 0 &&
            QString::compare(artifact->artifactName, chosenName, Qt::CaseInsensitive) < 0));
      if (betterRank || sameRankBetterTiebreak) {
        chosenRow = row;
        chosenRank = correlation.rank;
        chosenPath = artifact->sourceLogicalPath;
        chosenName = artifact->artifactName;
      }
    }

    QSignalBlocker blocker(&selectionModel);
    if (chosenRow < 0) {
      selectionModel.clearSelection();
      return false;
    }

    const QModelIndex proxyRow = artifactProxy.mapFromSource(artifactModel.index(chosenRow, 0));
    if (!proxyRow.isValid()) return false;
    selectionModel.select(proxyRow, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    return true;
  };

  {
    QSignalBlocker blocker(&selectionModel);
    selectionModel.select(proxyIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
  }

  if (silentSignalCount != 0) return 1;

  const auto selectedRows = selectionModel.selectedRows();
  if (selectedRows.size() != 1) return 1;
  if (selectedRows.first().row() != proxyIndex.row()) return 1;

  // Simulates the later "Artifacts tab opened" refresh path: selected artifact context must
  // remain resolvable even though the initial selection was silent.
  const QModelIndex selectedSource = artifactProxy.mapToSource(selectedRows.first());
  const auto *selectedArtifact = artifactModel.artifactAt(selectedSource.row());
  if (!selectedArtifact) return 1;
  if (selectedArtifact->artifactName != "A Exact") return 1;

  // Passive file->artifact synchronization should clear stale selection when no artifact correlates.
  if (!passiveSyncSelection("/Users/Alice/NTUSER.DAT")) return 1;
  if (selectionModel.selectedRows().size() != 1) return 1;
  if (passiveSyncSelection("/Windows/System32/kernel32.dll")) return 1;
  if (!selectionModel.selectedRows().isEmpty()) return 1;

  return 0;
}
