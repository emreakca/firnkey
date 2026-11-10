import { handleOffscreenMessage } from "./handlers";

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  const answer = handleOffscreenMessage(message);
  if (!answer) return false;
  void answer.then(sendResponse);
  return true;
});
