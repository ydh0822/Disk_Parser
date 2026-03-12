#include "ForensicImageExtractor/gui/FileEntryTableModel.h"

int runFileEntryFilteringTests() {
  fie::gui::FileEntryTableModel model;

  fie::domain::FileEntry a;
  a.name = "alpha.txt";
  a.fullPath = "/docs/alpha.txt";
  a.inode = 10;
  a.sizeBytes = 120;

  fie::domain::FileEntry b;
  b.name = "bravo.EXE";
  b.fullPath = "/bin/bravo.EXE";
  b.inode = 11;
  b.sizeBytes = 80;
  b.isDeleted = true;
  b.isAllocated = false;

  fie::domain::FileEntry c;
  c.name = "charlie";
  c.fullPath = "/tmp/charlie";
  c.inode = 12;
  c.isDirectory = true;

  model.setEntries({a, b, c});
  model.setStatusForPath("/bin/bravo.EXE", "extracted_with_warning");

  fie::gui::FileEntryFilterProxyModel proxy;
  proxy.setSourceModel(&model);

  proxy.setExtensionFilter(" .EXE ");
  if (proxy.rowCount() != 1) return 1;
  const QModelIndex extIdx = proxy.index(0, fie::gui::FileEntryTableModel::Name);
  if (proxy.data(extIdx).toString() != "bravo.EXE") return 1;

  proxy.setExtensionFilter({});
  proxy.setStatusContains("warning");
  if (proxy.rowCount() != 1) return 1;
  const QModelIndex statusIdx = proxy.index(0, fie::gui::FileEntryTableModel::Name);
  if (proxy.data(statusIdx).toString() != "bravo.EXE") return 1;

  proxy.setStatusContains({});
  proxy.setDeletedOnly(true);
  if (proxy.rowCount() != 1) return 1;
  proxy.setDeletedOnly(false);
  proxy.setDirectoriesOnly(true);
  if (proxy.rowCount() != 1) return 1;
  if (proxy.data(proxy.index(0, fie::gui::FileEntryTableModel::Name)).toString() != "charlie") return 1;


  proxy.setDirectoriesOnly(false);
  proxy.setAllocatedOnly(true);
  proxy.setPathContains("/docs");
  if (proxy.rowCount() != 1) return 1;
  if (proxy.data(proxy.index(0, fie::gui::FileEntryTableModel::Name)).toString() != "alpha.txt") return 1;
  proxy.setAllocatedOnly(false);
  proxy.setPathContains({});
  proxy.sort(fie::gui::FileEntryTableModel::Extension, Qt::AscendingOrder);
  if (proxy.rowCount() != 3) return 1;

  model.setStatusForPath("/docs/alpha.txt", "queued");
  model.setStatusForPath("/tmp/charlie", "archived");
  proxy.setStatusContains({});
  proxy.sort(fie::gui::FileEntryTableModel::Status, Qt::AscendingOrder);
  const QString firstByStatus = proxy.data(proxy.index(0, fie::gui::FileEntryTableModel::Name)).toString();
  if (firstByStatus != "charlie") return 1;

  return 0;
}
