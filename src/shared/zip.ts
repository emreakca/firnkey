// Reads one file out of a ZIP archive (stored or deflated, no ZIP64), using the browser's own
// DecompressionStream. Enough for 1Password's .1pux export, whose items are in "export.data".
export async function readZipEntry(archive: ArrayBuffer, name: string, maxBytes: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(archive);
  const view = new DataView(archive);
  // The end-of-central-directory record sits in the last 22 bytes plus an optional comment.
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 22 - 0xffff); offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) {
      end = offset;
      break;
    }
  }
  if (end < 0) throw new Error("The file is not a ZIP archive.");
  const count = view.getUint16(end + 10, true);
  let entry = view.getUint32(end + 16, true);
  for (let index = 0; index < count; index += 1) {
    if (entry + 46 > bytes.length || view.getUint32(entry, true) !== 0x02014b50) break;
    const method = view.getUint16(entry + 10, true);
    const compressedSize = view.getUint32(entry + 20, true);
    const size = view.getUint32(entry + 24, true);
    const nameLength = view.getUint16(entry + 28, true);
    const local = view.getUint32(entry + 42, true);
    const entryName = new TextDecoder().decode(bytes.subarray(entry + 46, entry + 46 + nameLength));
    entry += 46 + nameLength + view.getUint16(entry + 30, true) + view.getUint16(entry + 32, true);
    if (entryName !== name) continue;
    if (size > maxBytes) throw new Error("The file is too large to import.");
    if (local + 30 > bytes.length || view.getUint32(local, true) !== 0x04034b50) break;
    const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
    const data = bytes.subarray(start, start + compressedSize);
    if (method === 0) return data.slice();
    if (method !== 8) throw new Error("The ZIP archive uses an unsupported compression method.");
    const output = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer());
    if (output.length !== size) throw new Error("The ZIP archive is damaged.");
    return output;
  }
  throw new Error(`The archive has no ${name}.`);
}
