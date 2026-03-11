#pragma once

#include <QString>

namespace fie::utils {

enum class ErrorCode {
  None,
  InvalidPath,
  UnsupportedFormat,
  ParseFailure,
  FsOpenFailure,
  ReadFailure,
  Unknown,
};

class Error {
public:
  Error() = default;
  Error(ErrorCode code, QString message);

  ErrorCode code() const;
  const QString &message() const;
  bool hasError() const;

private:
  ErrorCode m_code{ErrorCode::None};
  QString m_message;
};

} // namespace fie::utils
