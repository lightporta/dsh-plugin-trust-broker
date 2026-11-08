import { constants } from 'node:fs';
import type { BigIntStats, Dirent } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';

export class FileReadLimitError extends Error {
  constructor() {
    super('file exceeds the remaining byte budget');
    this.name = 'FileReadLimitError';
  }
}

interface TreeFileOptions {
  rejectHardLinks?: boolean;
  signal?: AbortSignal;
}

function sameEntry(before: BigIntStats, after: BigIntStats): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.mode === after.mode &&
    before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

export async function assertTreeDirectory(path: string, expected?: BigIntStats): Promise<BigIntStats> {
  const current = await lstat(path, { bigint: true });
  if (!current.isDirectory()) {
    throw Object.assign(new Error('expected a regular directory'), { code: 'ENOTDIR' });
  }
  if (await realpath(path) !== path ||
      (expected !== undefined && !sameEntry(expected, current))) {
    throw new Error('directory is a link or changed during inspection');
  }
  return current;
}

/** Resolve caller-supplied ancestors, then refuse aliases below the canonical root. */
export async function canonicalTreeRoot(root: string, rejectRootLink = false): Promise<string> {
  const expected = rejectRootLink ? await lstat(root, { bigint: true }) : undefined;
  if (expected?.isSymbolicLink()) throw new Error('the root must not be a symbolic link');
  const canonical = await realpath(root);
  await assertTreeDirectory(canonical, expected);
  return canonical;
}

export async function treeDirectoryEntries(path: string): Promise<Dirent<string>[]> {
  const entries = await readdir(path, { withFileTypes: true, encoding: 'buffer' });
  return entries.map((entry) => {
    const name = entry.name.toString('utf8');
    if (!Buffer.from(name, 'utf8').equals(entry.name)) {
      throw new Error('directory contains a filename that is not valid UTF-8');
    }
    // Retain the directory-entry type methods without letting UTF-8 replacement alias a name.
    return Object.assign(entry, { name });
  });
}

/** Open a canonical regular file without following the leaf or blocking on a swapped FIFO. */
export async function withTreeFile<T>(
  file: string,
  options: TreeFileOptions,
  read: (handle: FileHandle, size: bigint) => Promise<T>,
): Promise<T> {
  options.signal?.throwIfAborted();
  const expected = await lstat(file, { bigint: true });
  if (!expected.isFile() || (options.rejectHardLinks === true && expected.nlink !== 1n)) {
    throw new Error('expected a regular file without a disallowed link');
  }
  if (await realpath(file) !== file) {
    throw new Error('file is outside its canonical path');
  }
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) |
    (constants.O_NONBLOCK ?? 0));
  try {
    const verify = async (): Promise<void> => {
      if (await realpath(file) !== file || !sameEntry(expected, await handle.stat({ bigint: true })) ||
          !sameEntry(expected, await lstat(file, { bigint: true }))) {
        throw new Error('file is outside its canonical path or changed during inspection');
      }
      options.signal?.throwIfAborted();
    };
    await verify();
    const result = await read(handle, expected.size);
    await verify();
    return result;
  } finally {
    await handle.close();
  }
}

export async function readTreeFile(file: string, maxBytes: number, options: TreeFileOptions = {}): Promise<Buffer> {
  return withTreeFile(file, options, async (handle, size) => {
    if (size > maxBytes) throw new FileReadLimitError();
    // Read at most one byte beyond the observed size to detect concurrent growth.
    const buffer = Buffer.alloc(Number(size) + 1);
    let offset = 0;
    while (offset < buffer.length) {
      options.signal?.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > maxBytes) throw new FileReadLimitError();
    if (offset !== Number(size)) throw new Error('file length changed during inspection');
    return buffer.subarray(0, offset);
  });
}
