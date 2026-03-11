#include "ForensicImageExtractor/core/EwfSegmentResolver.h"

#include <QFileInfo>
#include <QRegularExpression>
#include <algorithm>
#include <optional>

namespace fie::core {
namespace {
struct SegmentToken {
  QString baseLower;
  QString familyLower;
  int index;
};

std::optional<SegmentToken> parseEwfSegment(const QString &fileName) {
  static const QRegularExpression re(R"(^(.+)\.(e|ex|s)(\d{2})$)", QRegularExpression::CaseInsensitiveOption);
  const auto m = re.match(fileName);
  if (!m.hasMatch()) return std::nullopt;
  bool ok = false;
  const int idx = m.captured(3).toInt(&ok);
  if (!ok) return std::nullopt;
  return SegmentToken{m.captured(1).toLower(), m.captured(2).toLower(), idx};
}
} // namespace

bool isEwfPath(const QString &imagePath) {
  const auto name = QFileInfo(imagePath).fileName();
  return parseEwfSegment(name).has_value();
}

QStringList discoverEwfSegments(const QString &selectedPath,
                                const QStringList &fileNamesInDir,
                                QString *warning) {
  if (warning) warning->clear();

  QFileInfo selected(selectedPath);
  const auto parsedSelected = parseEwfSegment(selected.fileName());
  if (!parsedSelected) {
    return {selectedPath};
  }

  struct Candidate {
    QString absPath;
    int index;
  };
  std::vector<Candidate> candidates;

  for (const auto &name : fileNamesInDir) {
    const auto parsed = parseEwfSegment(name);
    if (!parsed) continue;
    if (parsed->baseLower != parsedSelected->baseLower) continue;
    if (parsed->familyLower != parsedSelected->familyLower) continue;
    candidates.push_back({selected.dir().absoluteFilePath(name), parsed->index});
  }

  if (candidates.empty()) {
    return {selectedPath};
  }

  std::sort(candidates.begin(), candidates.end(), [](const Candidate &a, const Candidate &b) {
    if (a.index != b.index) return a.index < b.index;
    return a.absPath < b.absPath;
  });

  if (warning) {
    QStringList missing;
    for (size_t i = 1; i < candidates.size(); ++i) {
      for (int expect = candidates[i - 1].index + 1; expect < candidates[i].index; ++expect) {
        missing << QString::number(expect);
      }
    }
    if (!missing.isEmpty()) {
      *warning = QString("Potential EWF segment gap detected; missing segment numbers: %1")
                     .arg(missing.join(','));
    }
  }

  QStringList out;
  for (const auto &c : candidates) out << c.absPath;
  return out;
}

} // namespace fie::core
