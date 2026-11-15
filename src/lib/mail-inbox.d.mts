import type { MailMessage } from './tauri';
export interface InboxMessage extends MailMessage {
  entryId: string;
  folder: string;
  accountEmail: string;
}
export function mailMessageKey(message: MailMessage & { entryId?: string; folder?: string }): string;
export function mergeMailInbox<T extends MailMessage & { entryId?: string; folder?: string }>(messages: T[]): T[];
