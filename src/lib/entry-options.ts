// Shared by desktop and mobile. Unknown stored values remain selectable.
export const DB_ENGINES = [
  { id: "mysql", label: "MySQL / MariaDB", port: 3306 },
  { id: "postgres", label: "PostgreSQL", port: 5432 },
  { id: "sqlserver", label: "SQL Server", port: 1433 },
  { id: "oracle", label: "Oracle", port: 1521 },
  { id: "mongodb", label: "MongoDB", port: 27017 },
  { id: "redis", label: "Redis", port: 6379 },
  { id: "sqlite", label: "SQLite", port: 0 },
  { id: "clickhouse", label: "ClickHouse", port: 8123 },
  { id: "elasticsearch", label: "Elasticsearch", port: 9200 },
  { id: "dameng", label: "达梦 DM", port: 5236 },
  { id: "custom", label: "其他", port: 0 },
];
export const SERVER_PROTOCOLS = [
  { id: "ssh", label: "SSH", port: 22 },
  { id: "rdp", label: "RDP", port: 3389 },
  { id: "sftp", label: "SFTP", port: 22 },
  { id: "ftp", label: "FTP", port: 21 },
  { id: "vnc", label: "VNC", port: 5900 },
];
export function optionsWithStored<T extends { id: string; label: string; port: number }>(options: T[], stored: string) {
  return !stored || options.some(option => option.id === stored)
    ? options : [...options, { id: stored, label: `${stored}（原值）`, port: 0 }];
}
export function databaseFields(engine: string) {
  return { host: engine !== "sqlite", port: engine !== "sqlite", username: engine !== "sqlite", databaseLabel: engine === "sqlite" ? "数据库文件路径" : engine === "oracle" ? "服务名 / SID" : engine === "redis" ? "数据库编号" : "数据库名" };
}
export function defaultPort(kind: string, value: string) {
  return (kind === "server" ? SERVER_PROTOCOLS : DB_ENGINES).find(option => option.id === value)?.port;
}
