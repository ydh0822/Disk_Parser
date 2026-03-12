#include "ForensicImageExtractor/gui/NavigationUtils.h"

int runNavigationUtilsTests() {
  using fie::gui::PendingSelectionOutcome;
  using fie::gui::pendingNavigationDecision;
  using fie::gui::pendingSelectionOutcome;

  const auto failedWithPending = pendingNavigationDecision(false, "/Users/Alice/NTUSER.DAT", "artifact context");
  if (failedWithPending.attemptFileSelection) return 1;
  if (failedWithPending.showCompletionMessage) return 1;
  if (!failedWithPending.clearPendingState) return 1;

  const auto successDirectoryJump = pendingNavigationDecision(true, "", "artifact dir context");
  if (successDirectoryJump.attemptFileSelection) return 1;
  if (!successDirectoryJump.showCompletionMessage) return 1;
  if (!successDirectoryJump.clearPendingState) return 1;

  const auto successFileJump = pendingNavigationDecision(true, "/Users/Alice/NTUSER.DAT", "artifact file context");
  if (!successFileJump.attemptFileSelection) return 1;
  if (successFileJump.showCompletionMessage) return 1;
  if (!successFileJump.clearPendingState) return 1;

  const auto idle = pendingNavigationDecision(true, "", "");
  if (idle.attemptFileSelection || idle.showCompletionMessage || idle.clearPendingState) return 1;


  if (pendingSelectionOutcome(false, "/Users/Alice/NTUSER.DAT", true, false) != PendingSelectionOutcome::None) return 1;
  if (pendingSelectionOutcome(true, "", true, false) != PendingSelectionOutcome::None) return 1;
  if (pendingSelectionOutcome(true, "/Users/Alice/NTUSER.DAT", true, true) != PendingSelectionOutcome::SelectedVisible) return 1;
  if (pendingSelectionOutcome(true, "/Users/Alice/NTUSER.DAT", true, false) != PendingSelectionOutcome::HiddenByFilters) return 1;
  if (pendingSelectionOutcome(true, "/Users/Alice/NTUSER.DAT", false, false) != PendingSelectionOutcome::NotFoundInLoadedDirectory) return 1;
  return 0;
}
