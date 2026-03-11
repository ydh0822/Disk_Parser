#include "ForensicImageExtractor/utils/Error.h"

namespace fie::utils {

Error::Error(ErrorCode code, QString message) : m_code(code), m_message(std::move(message)) {}
ErrorCode Error::code() const { return m_code; }
const QString &Error::message() const { return m_message; }
bool Error::hasError() const { return m_code != ErrorCode::None; }

} // namespace fie::utils
