export function completeChoices(conflicts, choices) {
  return conflicts.every(item => {
    const value = choices[item.id];
    return value && ['local', 'remote', 'both'].includes(value.choice) && (item.kind !== 'delete_edit' || value.confirm_delete_edit === true);
  });
}
export function buildResolutions(conflicts, choices) {
  if (!completeChoices(conflicts, choices)) throw new Error('请逐项选择，并确认删除与编辑冲突');
  return conflicts.map(item => ({ id: item.id, choice: choices[item.id].choice, confirm_delete_edit: choices[item.id].confirm_delete_edit === true }));
}
