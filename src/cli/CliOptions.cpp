#include "ForensicImageExtractor/cli/CliOptions.h"

#include <QCommandLineOption>
#include <QCommandLineParser>

namespace fie::cli {
namespace {

bool parseOverwrite(const QString &value, domain::OverwriteMode &mode) {
  if (value == "skip") {
    mode = domain::OverwriteMode::SkipExisting;
    return true;
  }
  if (value == "overwrite") {
    mode = domain::OverwriteMode::Overwrite;
    return true;
  }
  if (value == "versioned") {
    mode = domain::OverwriteMode::VersionedCopy;
    return true;
  }
  return false;
}

bool parseCommand(const QString &name, CommandType &type) {
  if (name == "inspect") {
    type = CommandType::Inspect;
    return true;
  }
  if (name == "list") {
    type = CommandType::List;
    return true;
  }
  if (name == "extract") {
    type = CommandType::Extract;
    return true;
  }
  if (name == "catalog") {
    type = CommandType::Catalog;
    return true;
  }
  return false;
}

} // namespace

QString usageText() {
  return "Usage:\n"
         "  fie_cli inspect --image <path> [--allow-path-fallback]\n"
         "  fie_cli list --image <path> --partition <id|index> [--path <dir>] [--allow-path-fallback]\n"
         "  fie_cli extract --image <path> --partition <id|index> --source <path> --dest <dir> [--overwrite skip|overwrite|versioned] [--md5] [--apply-host-timestamps] [--allow-path-fallback]\n"
         "  fie_cli catalog --image <path> --partition <id|index> --source <path> --dest <dir> --catalog-out <file> --catalog-format json|csv [--overwrite skip|overwrite|versioned] [--md5] [--apply-host-timestamps] [--allow-path-fallback]";
}

bool parseOptions(const QStringList &args, ParsedOptions &out, QString &error) {
  QCommandLineParser parser;
  parser.setSingleDashWordOptionMode(QCommandLineParser::ParseAsLongOptions);

  QCommandLineOption imageOpt("image", "Image path", "path");
  QCommandLineOption partitionOpt("partition", "Partition identifier/index", "partition", "p0");
  QCommandLineOption pathOpt("path", "Directory path to list", "path", "/");
  QCommandLineOption sourceOpt("source", "Source file/directory path", "path");
  QCommandLineOption destOpt("dest", "Destination root directory", "directory");
  QCommandLineOption catalogOutOpt("catalog-out", "Catalog output file path", "path");
  QCommandLineOption catalogFormatOpt("catalog-format", "Catalog format (json|csv)", "format", "json");
  QCommandLineOption overwriteOpt("overwrite", "Overwrite mode (skip|overwrite|versioned)", "mode", "skip");
  QCommandLineOption md5Opt("md5", "Compute MD5 in addition to SHA-256");
  QCommandLineOption applyTsOpt("apply-host-timestamps", "Apply host timestamps to extracted output");
  QCommandLineOption fallbackOpt("allow-path-fallback", "Allow path-based TSK compatibility fallback");

  parser.addOption(imageOpt);
  parser.addOption(partitionOpt);
  parser.addOption(pathOpt);
  parser.addOption(sourceOpt);
  parser.addOption(destOpt);
  parser.addOption(catalogOutOpt);
  parser.addOption(catalogFormatOpt);
  parser.addOption(overwriteOpt);
  parser.addOption(md5Opt);
  parser.addOption(applyTsOpt);
  parser.addOption(fallbackOpt);
  parser.addPositionalArgument("command", "inspect | list | extract | catalog");

  if (!parser.parse(args)) {
    error = parser.errorText();
    return false;
  }

  const auto positional = parser.positionalArguments();
  if (positional.size() != 1 || !parseCommand(positional.first(), out.command)) {
    error = "Missing or invalid command";
    return false;
  }

  out.imagePath = parser.value(imageOpt).trimmed();
  out.partition = parser.value(partitionOpt).trimmed();
  out.listPath = parser.value(pathOpt).trimmed();
  out.sourcePath = parser.value(sourceOpt).trimmed();
  out.destinationRoot = parser.value(destOpt).trimmed();
  out.catalogPath = parser.value(catalogOutOpt).trimmed();
  out.catalogFormat = parser.value(catalogFormatOpt).trimmed().toLower();
  out.allowPathFallback = parser.isSet(fallbackOpt);
  out.computeMd5 = parser.isSet(md5Opt);
  out.applyHostTimestamps = parser.isSet(applyTsOpt);

  if (!parseOverwrite(parser.value(overwriteOpt).trimmed().toLower(), out.overwriteMode)) {
    error = "Invalid overwrite mode";
    return false;
  }

  if (out.imagePath.isEmpty()) {
    error = "--image is required";
    return false;
  }

  if (out.command == CommandType::List && out.listPath.isEmpty()) {
    error = "--path must not be empty";
    return false;
  }

  if (out.command == CommandType::Extract || out.command == CommandType::Catalog) {
    if (out.sourcePath.isEmpty()) {
      error = "--source is required";
      return false;
    }
    if (out.destinationRoot.isEmpty()) {
      error = "--dest is required";
      return false;
    }
  }

  if (out.command == CommandType::Catalog) {
    if (out.catalogPath.isEmpty()) {
      error = "--catalog-out is required for catalog command";
      return false;
    }
    if (out.catalogFormat != "json" && out.catalogFormat != "csv") {
      error = "--catalog-format must be json or csv";
      return false;
    }
  }

  return true;
}

} // namespace fie::cli
