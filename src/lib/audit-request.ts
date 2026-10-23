export function createAuditRequestGuard() {
  let generation = 0;
  return {
    begin: () => ++generation,
    invalidate: () => { generation++; },
    isCurrent: (request: number) => request === generation,
  };
}

export function auditDateBounds(from: string, to: string) {
  const start = from ? new Date(`${from}T00:00:00`) : null;
  const end = to ? new Date(`${to}T00:00:00`) : null;
  if (end) end.setDate(end.getDate() + 1);
  if ((start && Number.isNaN(start.getTime())) || (end && Number.isNaN(end.getTime())) || (start && end && start >= end)) {
    throw new Error("请选择有效且起始不晚于结束的日期");
  }
  return { from: start?.toISOString() ?? null, to: end?.toISOString() ?? null };
}
