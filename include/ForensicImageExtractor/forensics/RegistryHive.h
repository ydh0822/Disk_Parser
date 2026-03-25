#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>

#include <optional>
#include <memory>
#include <vector>

namespace fie::forensics {

class RegistryHive {
public:
  struct Value {
    QString name;
    quint32 type{0};
    QByteArray rawData;
  };

  struct Key {
    QString path;
    std::optional<QDateTime> lastWrite;
    std::vector<Value> values;
  };

  bool open(const QByteArray &bytes, QString &error);
  std::optional<Key> keyByPath(const QString &path, QString &error) const;
  std::vector<Key> childKeys(const QString &path, QString &error) const;

private:
  struct State;
  std::unique_ptr<State> m_state;
};

QString decodeRegistryString(const RegistryHive::Value &value);
std::optional<quint32> decodeRegistryDword(const RegistryHive::Value &value);

} // namespace fie::forensics
