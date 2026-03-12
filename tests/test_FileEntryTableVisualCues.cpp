#include "ForensicImageExtractor/gui/FileEntryTableModel.h"

#include <QBrush>

int runFileEntryTableVisualCueTests() {
  fie::gui::FileEntryTableModel model;

  fie::domain::FileEntry deleted;
  deleted.name = "deleted.bin";
  deleted.fullPath = "/deleted.bin";
  deleted.isDeleted = true;
  deleted.isAllocated = false;

  fie::domain::FileEntry ads;
  ads.name = "streamed.txt";
  ads.fullPath = "/streamed.txt";
  fie::domain::NtfsMetadata ntfs;
  ntfs.hasAds = true;
  ntfs.adsNames = {"Zone.Identifier"};
  ads.metadata.ntfs = ntfs;

  fie::domain::FileEntry clean;
  clean.name = "clean.txt";
  clean.fullPath = "/clean.txt";

  model.setEntries({deleted, ads, clean});
  model.setStatusForPath("/deleted.bin", "warning_short_read");
  model.setStatusForPath("/clean.txt", "processing 20/100");

  const QModelIndex deletedIdx = model.index(0, fie::gui::FileEntryTableModel::Deleted);
  if (model.data(deletedIdx, Qt::DisplayRole).toString() != "Yes") return 1;
  if (!model.data(deletedIdx, Qt::ForegroundRole).canConvert<QBrush>()) return 1;
  if (!model.data(deletedIdx, Qt::FontRole).isValid()) return 1;
  if (model.data(deletedIdx, Qt::ToolTipRole).toString().isEmpty()) return 1;

  const QModelIndex adsIdx = model.index(1, fie::gui::FileEntryTableModel::Ads);
  if (model.data(adsIdx, Qt::DisplayRole).toString().isEmpty()) return 1;
  if (!model.data(adsIdx, Qt::ForegroundRole).canConvert<QBrush>()) return 1;

  const QModelIndex statusIdx = model.index(0, fie::gui::FileEntryTableModel::Status);
  if (model.data(statusIdx, Qt::DisplayRole).toString() != "warning_short_read") return 1;
  if (!model.data(statusIdx, Qt::ForegroundRole).canConvert<QBrush>()) return 1;
  if (!model.data(statusIdx, Qt::FontRole).isValid()) return 1;

  const QModelIndex processingIdx = model.index(2, fie::gui::FileEntryTableModel::Status);
  if (!model.data(processingIdx, Qt::ForegroundRole).canConvert<QBrush>()) return 1;
  if (model.data(processingIdx, Qt::FontRole).isValid()) return 1;
  if (model.data(processingIdx, Qt::ToolTipRole).toString().isEmpty()) return 1;

  const QModelIndex cleanDeleted = model.index(2, fie::gui::FileEntryTableModel::Deleted);
  if (model.data(cleanDeleted, Qt::ForegroundRole).isValid()) return 1;

  return 0;
}
