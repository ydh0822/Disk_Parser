#pragma once

#include "ForensicImageExtractor/domain/Models.h"

#include <QByteArray>

#include <functional>
#include <memory>
#include <vector>

namespace fie::forensics {

struct ArtifactDetailRequest {
  std::function<QByteArray(const QString &, QString &)> readBytes;
};

class IArtifactDetailProvider {
public:
  virtual ~IArtifactDetailProvider() = default;
  virtual QString name() const = 0;
  virtual bool supports(const domain::ArtifactRecord &artifact) const = 0;
  virtual domain::ArtifactDetails parse(const domain::ArtifactRecord &artifact,
                                        const ArtifactDetailRequest &request) const = 0;
};

class ArtifactDetailService {
public:
  ArtifactDetailService();
  explicit ArtifactDetailService(std::vector<std::unique_ptr<IArtifactDetailProvider>> providers);

  std::optional<domain::ArtifactDetails> describe(const domain::ArtifactRecord &artifact,
                                                  const ArtifactDetailRequest &request) const;
  void populate(std::vector<domain::ArtifactRecord> &artifacts,
                const ArtifactDetailRequest &request,
                QStringList &warnings) const;

private:
  std::vector<std::unique_ptr<IArtifactDetailProvider>> m_providers;
};

} // namespace fie::forensics
