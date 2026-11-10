import type { SyncResponse } from "../api/models";

const VAULT_STORE = "encryptedVault";
const CURRENT_RECORD = "current";

// Opens `database` (one store, keyed by `id`), runs one request in its own transaction, then closes it.
export function idbRequest<T>(
  database: string,
  store: string,
  mode: IDBTransactionMode,
  run: (objectStore: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(database, 1);
    open.onupgradeneeded = () => {
      if (!open.result.objectStoreNames.contains(store)) open.result.createObjectStore(store, { keyPath: "id" });
    };
    open.onerror = () => reject(new Error(`The ${database} database could not be opened.`));
    open.onblocked = () => reject(new Error(`The ${database} database upgrade was blocked.`));
    open.onsuccess = () => {
      const connection = open.result;
      try {
        const request = run(connection.transaction(store, mode).objectStore(store));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error(`The ${database} database operation failed.`));
      } catch (error) {
        reject(error);
      } finally {
        connection.close(); // Waits for the pending transaction to finish.
      }
    };
  });
}

// `id` defaults to the active account; switched-out accounts keep their copy under their own id.
export async function writeEncryptedSync(payload: SyncResponse, id = CURRENT_RECORD): Promise<void> {
  await idbRequest("firnkey", VAULT_STORE, "readwrite", (store) => store.put({ id, payload }));
}

export async function readEncryptedSync(id = CURRENT_RECORD): Promise<SyncResponse | null> {
  const record = await idbRequest<{ payload: SyncResponse } | undefined>("firnkey", VAULT_STORE, "readonly", (store) => store.get(id));
  return record?.payload ?? null;
}

export async function clearEncryptedSync(id = CURRENT_RECORD): Promise<void> {
  await idbRequest("firnkey", VAULT_STORE, "readwrite", (store) => store.delete(id));
}
