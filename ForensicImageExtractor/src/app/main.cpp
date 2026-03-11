#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/gui/MainWindow.h"

#include <QApplication>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  qRegisterMetaType<fie::domain::ImageInfo>("fie::domain::ImageInfo");
  qRegisterMetaType<std::vector<fie::domain::PartitionInfo>>("std::vector<fie::domain::PartitionInfo>");
  qRegisterMetaType<std::vector<fie::domain::FileEntry>>("std::vector<fie::domain::FileEntry>");
  qRegisterMetaType<std::vector<fie::domain::ExtractionResult>>("std::vector<fie::domain::ExtractionResult>");

  fie::gui::MainWindow w;
  w.show();
  return app.exec();
}
