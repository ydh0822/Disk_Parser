#pragma once

#include <QString>

namespace fie::gui {

struct PendingNavigationDecision {
  bool attemptFileSelection{false};
  bool showCompletionMessage{false};
  bool clearPendingState{false};
};

enum class PendingSelectionOutcome {
  None,
  SelectedVisible,
  HiddenByFilters,
  NotFoundInLoadedDirectory,
};

// Decides whether a completed directory-list operation should drive file selection,
// completion messaging, and pending-state cleanup.
inline PendingNavigationDecision pendingNavigationDecision(bool listingSucceeded,
                                                          const QString &pendingFileSelectionPath,
                                                          const QString &pendingNavigationContext) {
  if (!listingSucceeded) return {false, false, true};
  if (!pendingFileSelectionPath.isEmpty()) return {true, false, true};
  if (!pendingNavigationContext.isEmpty()) return {false, true, true};
  return {false, false, false};
}


// Classifies a pending file-selection attempt after a successful listing.
inline PendingSelectionOutcome pendingSelectionOutcome(bool listingSucceeded,
                                                       const QString &pendingFileSelectionPath,
                                                       bool sourceEntryExists,
                                                       bool selectedInVisibleRows) {
  if (!listingSucceeded || pendingFileSelectionPath.isEmpty()) return PendingSelectionOutcome::None;
  if (selectedInVisibleRows) return PendingSelectionOutcome::SelectedVisible;
  return sourceEntryExists ? PendingSelectionOutcome::HiddenByFilters
                           : PendingSelectionOutcome::NotFoundInLoadedDirectory;
}

} // namespace fie::gui
