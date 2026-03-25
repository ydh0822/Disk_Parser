#pragma once

#include "ForensicImageExtractor/cli/ArtifactJson.h"
#include "ForensicImageExtractor/domain/Models.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <algorithm>
#include <vector>

namespace fie::cli {

inline QJsonObject artifactEventToJson(const domain::ArtifactEventRecord &event) {
  QJsonObject obj;
  obj["timestamp"] = event.timestamp ? QJsonValue(event.timestamp->toString(Qt::ISODate)) : QJsonValue::Null;
  obj["event_type"] = event.eventType;
  obj["category"] = event.category;
  obj["artifact_name"] = event.artifactName;
  obj["profile"] = event.profile;
  obj["source_logical_path"] = event.sourceLogicalPath;
  obj["partition_identifier"] = event.partitionIdentifier;
  obj["filesystem_type"] = event.fileSystemType;
  obj["parser_provider"] = event.parserProvider;
  obj["parse_state"] = parseStateToString(event.parseState);
  obj["summary"] = event.summary.isEmpty() ? QJsonValue::Null : QJsonValue(event.summary);
  obj["note"] = event.note.isEmpty() ? QJsonValue::Null : QJsonValue(event.note);

  QJsonObject fields;
  for (const auto &field : event.fields) {
    fields[field.key] = field.value ? QJsonValue(*field.value) : QJsonValue::Null;
  }
  obj["fields"] = fields;
  return obj;
}

inline QJsonArray artifactEventsToJsonArray(const std::vector<domain::ArtifactEventRecord> &events) {
  QJsonArray out;
  for (const auto &event : events) out.append(artifactEventToJson(event));
  return out;
}

inline QString artifactEventsToCsv(std::vector<domain::ArtifactEventRecord> events) {
  auto quote = [](const QString &value) {
    QString escaped = value;
    escaped.replace('"', "\"\"");
    return QString("\"%1\"").arg(escaped);
  };

  const auto json = artifactEventsToJsonArray(std::move(events));
  QStringList lines;
  lines << "timestamp,event_type,category,artifact_name,profile,source_logical_path,partition_identifier,filesystem_type,parser_provider,parse_state,summary,note,fields_json";
  for (const auto &v : json) {
    const auto o = v.toObject();
    const auto fieldsJson = QString::fromUtf8(QJsonDocument(o.value("fields").toObject()).toJson(QJsonDocument::Compact));
    lines << QString("%1,%2,%3,%4,%5,%6,%7,%8,%9,%10,%11,%12,%13")
                 .arg(quote(o.value("timestamp").isNull() ? QString() : o.value("timestamp").toString()),
                      quote(o.value("event_type").toString()),
                      quote(o.value("category").toString()),
                      quote(o.value("artifact_name").toString()),
                      quote(o.value("profile").toString()),
                      quote(o.value("source_logical_path").toString()),
                      quote(o.value("partition_identifier").toString()),
                      quote(o.value("filesystem_type").toString()),
                      quote(o.value("parser_provider").toString()),
                      quote(o.value("parse_state").toString()),
                      quote(o.value("summary").isNull() ? QString() : o.value("summary").toString()),
                      quote(o.value("note").isNull() ? QString() : o.value("note").toString()),
                      quote(fieldsJson));
  }
  return lines.join('\n');
}

} // namespace fie::cli
