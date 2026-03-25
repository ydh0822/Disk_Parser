#include "ForensicImageExtractor/forensics/ArtifactDetailProviders.h"

#include <QFile>
#include <QTemporaryFile>

#if defined(FIE_HAS_SQLITE)
#include <sqlite3.h>
#endif

int runBrowserHistoryProviderTests() {
  fie::forensics::ArtifactDetailService service;
  fie::domain::ArtifactRecord artifact;
  artifact.artifactName = "Chrome History";
  artifact.sourceLogicalPath = "/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History";

#if defined(FIE_HAS_SQLITE)
  QTemporaryFile dbFile("fie_history_XXXXXX.db");
  if (!dbFile.open()) return 1;
  const QString dbPath = dbFile.fileName();
  dbFile.close();

  sqlite3 *db = nullptr;
  if (sqlite3_open(dbPath.toUtf8().constData(), &db) != SQLITE_OK) return 1;
  const char *schema1 = "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);";
  const char *schema2 = "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);";
  const char *schema3 = "CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, start_time INTEGER);";
  sqlite3_exec(db, schema1, nullptr, nullptr, nullptr);
  sqlite3_exec(db, schema2, nullptr, nullptr, nullptr);
  sqlite3_exec(db, schema3, nullptr, nullptr, nullptr);
  sqlite3_exec(db, "INSERT INTO urls(id,url,title,visit_count) VALUES(1,'https://example.com','Example',5);", nullptr, nullptr, nullptr);
  sqlite3_exec(db, "INSERT INTO visits(url,visit_time) VALUES(1,13253760000000000);", nullptr, nullptr, nullptr);
  sqlite3_exec(db, "INSERT INTO downloads(tab_url,target_path,start_time) VALUES('https://example.com/a.zip','C:/Users/Alice/Downloads/a.zip',13253760000000000);", nullptr, nullptr, nullptr);
  sqlite3_close(db);

  QFile file(dbPath);
  if (!file.open(QIODevice::ReadOnly)) return 1;
  const QByteArray bytes = file.readAll();
  const auto details = service.describe(artifact, {[&bytes](const QString &, QString &) { return bytes; }});
  if (!details.has_value()) return 1;
  if (details->state == fie::domain::ArtifactParseState::Failed) return 1;
  if (details->browserVisits.empty()) return 1;
  if (details->browserDownloads.empty()) return 1;
#else
  const auto details = service.describe(artifact, {[](const QString &, QString &) { return QByteArray(); }});
  if (!details.has_value()) return 1;
  if (details->state != fie::domain::ArtifactParseState::Unsupported) return 1;
#endif

  return 0;
}
