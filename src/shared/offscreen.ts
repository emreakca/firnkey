import { handleOffscreenMessage } from "../offscreen/handlers";

const OFFSCREEN_PATH = "offscreen/index.html";

let queue: Promise<unknown> = Promise.resolve();

// Chrome allows one offscreen document per extension, so uses run one at a time and close it afterwards.
function withOffscreenDocument<T>(task: () => Promise<T>): Promise<T> {
  const run = queue.then(async () => {
    await ensureOffscreenDocument();
    try {
      return await task();
    } finally {
      await closeOffscreenDocument();
    }
  });
  queue = run.catch(() => undefined);
  return run;
}

// Sends a message to the offscreen document. Firefox has none, but its background is a page with a
// DOM, so the same handlers run right there.
export function offscreenRequest(message: Record<string, unknown>): Promise<unknown> {
  const request = { target: "firnkey-offscreen", ...message };
  return __FIREFOX__
    ? handleOffscreenMessage(request) ?? Promise.resolve(undefined)
    : withOffscreenDocument(() => chrome.runtime.sendMessage(request));
}

// With a digest, only clears when the clipboard still holds the value Firnkey copied.
export async function clearClipboard(digest?: string | null): Promise<void> {
  await offscreenRequest({ type: "clipboard.clear", ...(digest ? { digest } : {}) });
}

async function ensureOffscreenDocument(): Promise<void> {
  const contexts = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
    documentUrls: [chrome.runtime.getURL(OFFSCREEN_PATH)],
  });
  if (contexts.length === 0) {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      reasons: [chrome.offscreen.Reason.WORKERS, chrome.offscreen.Reason.CLIPBOARD],
      justification: "Derive an Argon2id master key, or clear a copied secret from the clipboard.",
    });
  }
}

async function closeOffscreenDocument(): Promise<void> {
  try {
    await chrome.offscreen.closeDocument();
  } catch {
    // The document may already have been closed during extension shutdown.
  }
}
