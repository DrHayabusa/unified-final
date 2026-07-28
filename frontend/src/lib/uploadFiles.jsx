export function uploadFileKey(file) {
  return String(file?.name ?? "").trim().toLowerCase();
}

export function isSupportedUploadFile(file) {
  return /\.(?:csv|xlsx)$/i.test(String(file?.name ?? ""));
}

export function mergeUploadFiles(currentFiles, incomingFiles) {
  const merged = Array.from(currentFiles ?? []);
  const indexes = new Map(merged.map((file, index) => [uploadFileKey(file), index]));

  for (const file of Array.from(incomingFiles ?? [])) {
    const key = uploadFileKey(file);
    if (!key) continue;

    const existingIndex = indexes.get(key);
    if (existingIndex === undefined) {
      indexes.set(key, merged.length);
      merged.push(file);
    } else {
      // A newly selected export with the same name replaces the older copy.
      merged[existingIndex] = file;
    }
  }

  return merged;
}

export function removeUploadFile(files, fileToRemove) {
  const key = uploadFileKey(fileToRemove);
  return Array.from(files ?? []).filter((file) => uploadFileKey(file) !== key);
}
