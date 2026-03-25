#include "ForensicImageExtractor/gui/ArtifactDetailSession.h"

int runArtifactDetailSessionTests() {
  fie::domain::ArtifactRecord artifact;
  artifact.partitionIdentifier = "p1";
  artifact.sourceLogicalPath = "/Users/Alice/Recent/test.lnk";

  const QString key = fie::gui::artifactDetailCacheKey(artifact);
  if (key != "p1|/users/alice/recent/test.lnk") return 1;

  fie::gui::ArtifactDetailSessionCache cache;
  if (cache.contains(key)) return 1;
  if (cache.get(key).has_value()) return 1;

  // unsupported cached as explicit nullopt value
  cache.put(key, std::nullopt);
  if (!cache.contains(key)) return 1;
  const auto unsupported = cache.get(key);
  if (!unsupported.has_value()) return 1;
  if (unsupported->has_value()) return 1;

  fie::domain::ArtifactDetails details;
  details.provider = "windows.lnk_summary";
  details.state = fie::domain::ArtifactParseState::Parsed;
  cache.put(key, details);
  const auto loaded = cache.get(key);
  if (!loaded.has_value() || !loaded->has_value()) return 1;
  if (loaded->value().provider != "windows.lnk_summary") return 1;

  cache.clear();
  if (cache.contains(key)) return 1;

  // stale-result suppression policy
  if (!fie::gui::shouldApplyArtifactDetailResult(5, key, key, 5, key)) return 1;
  if (fie::gui::shouldApplyArtifactDetailResult(5, key, key, 4, key)) return 1;
  if (fie::gui::shouldApplyArtifactDetailResult(5, key, "p1|/other", 5, key)) return 1;
  if (fie::gui::shouldApplyArtifactDetailResult(5, key, key, 5, "p1|/other")) return 1;

  return 0;
}
