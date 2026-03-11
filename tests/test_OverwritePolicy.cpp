#include "ForensicImageExtractor/domain/Models.h"
#include "ForensicImageExtractor/utils/ExtractionPlanner.h"

#include <QFile>

int runOverwritePolicyTests() {
  const QString base = "/tmp/fie_overwrite_test.bin";
  QFile(base).remove();
  {
    QFile f(base);
    if (!f.open(QIODevice::WriteOnly)) return 1;
    f.write("x");
  }

  QString decision;
  const auto skip = fie::utils::resolveDestinationPath(base, fie::domain::OverwriteMode::SkipExisting, decision);
  if (decision != "skipped_existing" || skip != base) return 1;

  const auto overwrite =
      fie::utils::resolveDestinationPath(base, fie::domain::OverwriteMode::Overwrite, decision);
  if (decision != "overwrite" || overwrite != base) return 1;

  const auto versioned =
      fie::utils::resolveDestinationPath(base, fie::domain::OverwriteMode::VersionedCopy, decision);
  if (decision != "versioned_copy" || versioned == base) return 1;

  QFile(base).remove();
  return 0;
}
