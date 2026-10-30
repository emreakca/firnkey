const OFFSCREEN_PATH = "offscreen/index.html";

let queue: Promise<unknown> = Promise.resolve();

// Chrome allows one offscreen document per extension, so uses run one at a time and close it afterwards.
export function withOffscreenDocument<T>(task: () => Promise<T>): Promise<T> {
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

// With a digest, only clears when the clipboard still holds the value Firnkey copied.
export async function clearClipboard(digest?: string | null): Promise<void> {
  await withOffscreenDocument(() =>
    chrome.runtime.sendMessage({ target: "firnkey-offscreen", type: "clipboard.clear", ...(digest ? { digest } : {}) }),
  );
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
