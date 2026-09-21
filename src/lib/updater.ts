import { check, type DownloadEvent, type Update } from "@tauri-apps/plugin-updater";

export const RELEASE_PAGE_URL = "https://github.com/hahaha-taotao/sealbox/releases/latest";

export interface UpdaterMetadata {
  currentVersion: string;
  latestVersion: string;
  publishedAt: string | null;
  notes: string | null;
  releaseUrl: string;
}

export interface AvailableUpdate {
  handle: Update;
  metadata: UpdaterMetadata;
}

export type NormalizedDownloadEvent =
  | {
      phase: "started";
      contentLength: number | null;
      downloadedBytes: number;
      chunkLength: 0;
    }
  | {
      phase: "progress";
      contentLength: number | null;
      downloadedBytes: number;
      chunkLength: number;
    }
  | {
      phase: "finished";
      contentLength: number | null;
      downloadedBytes: number;
      chunkLength: 0;
    };

export function normalizeDownloadEvent(
  event: DownloadEvent,
  downloadedBytes: number,
  contentLength: number | null,
): NormalizedDownloadEvent {
  switch (event.event) {
    case "Started":
      return {
        phase: "started",
        contentLength: event.data.contentLength ?? null,
        downloadedBytes: 0,
        chunkLength: 0,
      };
    case "Progress":
      return {
        phase: "progress",
        contentLength,
        downloadedBytes: downloadedBytes + event.data.chunkLength,
        chunkLength: event.data.chunkLength,
      };
    case "Finished":
      return {
        phase: "finished",
        contentLength,
        downloadedBytes,
        chunkLength: 0,
      };
  }
}

export async function checkForUpdate(): Promise<AvailableUpdate | null> {
  const handle = await check();
  if (!handle) return null;
  return {
    handle,
    metadata: {
      currentVersion: handle.currentVersion,
      latestVersion: handle.version,
      publishedAt: handle.date ?? null,
      notes: handle.body ?? null,
      releaseUrl: RELEASE_PAGE_URL,
    },
  };
}

export async function download(
  update: AvailableUpdate,
  onProgress?: (event: NormalizedDownloadEvent) => void,
): Promise<void> {
  let downloadedBytes = 0;
  let contentLength: number | null = null;
  await update.handle.download((event) => {
    if (event.event === "Started") contentLength = event.data.contentLength ?? null;
    const normalized = normalizeDownloadEvent(event, downloadedBytes, contentLength);
    downloadedBytes = normalized.downloadedBytes;
    contentLength = normalized.contentLength;
    onProgress?.(normalized);
  });
}

export function install(update: AvailableUpdate): Promise<void> {
  // On Windows the updater launches the signed NSIS installer and exits the app.
  // The installer restarts the updated application after it replaces the files.
  return update.handle.install({ restartAfterInstall: true });
}
