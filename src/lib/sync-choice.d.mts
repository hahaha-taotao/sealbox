export interface ConflictItem { id: string; kind: string }
export interface SyncChoice { choice: 'local' | 'remote' | 'both' | ''; confirm_delete_edit: boolean }
export function completeChoices(conflicts: ConflictItem[], choices: Record<string, SyncChoice>): boolean;
export function buildResolutions(conflicts: ConflictItem[], choices: Record<string, SyncChoice>): {id: string; choice: string; confirm_delete_edit: boolean}[];
