// tiny IndexedDB key-value store. everything written here is already
// sealed with the vault key (except the vault key itself, which has to
// live somewhere on the device, the same call Signal Desktop makes).

let dbp;

function db() {
  dbp ??= new Promise((resolve, reject) => {
    const req = indexedDB.open("plutonetwork", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("kv");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbp;
}

const op = (mode, fn) =>
  db().then(
    (d) =>
      new Promise((resolve, reject) => {
        const tx = d.transaction("kv", mode);
        const req = fn(tx.objectStore("kv"));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      })
  );

export const idbGet = (key) => op("readonly", (s) => s.get(key));
export const idbPut = (key, val) => op("readwrite", (s) => s.put(val, key));
export const idbDel = (key) => op("readwrite", (s) => s.delete(key));
