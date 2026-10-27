//! Desktop filesystem boundary; secrets never leave Rust through preview DTOs.
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Write}, path::Path, time::{Duration, Instant}};
use zeroize::Zeroizing;
pub const CSV_LIMIT: usize = 5 * 1024 * 1024;
const TTL: Duration = Duration::from_secs(600);
const INVALID: &str = "预览已失效，请重新预览";
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind { Backup, Csv }
pub struct Pending {
    pub bytes: Zeroizing<Vec<u8>>,
    pub password: Zeroizing<String>,
    kind: Kind, hash: [u8; 32], token: String, created: Instant,
}
#[derive(Default)]
pub struct TransferCache { pending: Option<Pending> }
impl TransferCache {
    pub fn clear(&mut self) { self.pending = None; }
    pub fn put(&mut self, kind: Kind, bytes: Zeroizing<Vec<u8>>, password: Zeroizing<String>) -> String {
        let mut random = [0; 32]; OsRng.fill_bytes(&mut random);
        let token = hex::encode(random);
        self.pending = Some(Pending { kind, hash: Sha256::digest(&*bytes).into(), bytes, password, token: token.clone(), created: Instant::now() });
        token
    }
    pub fn take(&mut self, token: &str, kind: Kind) -> Result<Pending, String> {
        let item = self.pending.take().ok_or(INVALID)?;
        let hash: [u8; 32] = Sha256::digest(&*item.bytes).into();
        if item.token != token || item.kind != kind || item.created.elapsed() >= TTL || hash != item.hash { return Err(INVALID.into()); }
        Ok(item)
    }
}
fn absolute(path: &str) -> Result<&Path, String> {
    let path = Path::new(path);
    if !path.is_absolute() || path.file_name().is_none() { return Err("请选择绝对文件路径".into()); }
    Ok(path)
}
pub fn read_bounded(path: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(absolute(path)?).map_err(|_| "无法读取所选文件")?;
    let meta = file.metadata().map_err(|_| "无法读取文件信息")?;
    if !meta.is_file() || meta.len() > limit as u64 { return Err("文件类型无效或超过大小限制".into()); }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| "读取文件失败")?;
    if bytes.len() > limit { return Err("文件超过大小限制".into()); }
    Ok(bytes)
}
pub fn write_atomic(path: &str, bytes: &[u8]) -> Result<(), String> {
    let target = absolute(path)?;
    let temporary = target.parent().ok_or("目标目录无效")?.join(format!(".sealbox-export-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|_| "无法创建导出临时文件")?;
    let result = (|| { file.write_all(bytes)?; file.sync_all()?; drop(file); replace(&temporary, target) })();
    if result.is_err() { return Err(format!("导出未完成，未主动删除原目标；请清理临时文件 {} 后重试", temporary.display())); }
    Ok(())
}
#[cfg(windows)]
fn replace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" { fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32; }
    let a: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let b: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 0x1 | 0x8) } == 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}
#[cfg(not(windows))]
fn replace(source: &Path, target: &Path) -> std::io::Result<()> { std::fs::rename(source, target) }
#[cfg(test)]
mod tests {
    use super::*;
    fn put(c: &mut TransferCache) -> String { c.put(Kind::Csv, Zeroizing::new(b"original A".to_vec()), Zeroizing::new(String::new())) }
    #[test]
    fn single_use_original_bytes_and_invalidation() {
        let mut c = TransferCache::default(); let a = put(&mut c); let b = put(&mut c); assert_ne!(a,b);
        assert_eq!(&*c.take(&b,Kind::Csv).unwrap().bytes,b"original A"); assert!(c.take(&b,Kind::Csv).is_err());
        let t = put(&mut c); c.clear(); assert!(c.take(&t,Kind::Csv).is_err());
    }
    #[test]
    fn wrong_token_kind_expiry_and_tamper_fail_closed() {
        let mut c = TransferCache::default(); let t=put(&mut c); assert!(c.take("wrong",Kind::Csv).is_err()); assert!(c.take(&t,Kind::Csv).is_err());
        let t=put(&mut c); assert!(c.take(&t,Kind::Backup).is_err());
        let t=put(&mut c); c.pending.as_mut().unwrap().created=Instant::now()-TTL; assert!(c.take(&t,Kind::Csv).is_err());
        let t=put(&mut c); c.pending.as_mut().unwrap().bytes[0]^=1; assert!(c.take(&t,Kind::Csv).is_err());
    }
    #[test]
    fn bounded_read_and_replacement() {
        let root=std::env::temp_dir().join(format!("sealbox-transfer-{}",uuid::Uuid::new_v4())); std::fs::create_dir(&root).unwrap();
        let path=root.join("export.csv"); let p=path.to_str().unwrap(); std::fs::write(&path,b"old").unwrap();
        assert!(read_bounded(p,2).is_err()); assert!(read_bounded("relative",20).is_err());
        write_atomic(p,b"new").unwrap(); assert_eq!(&*read_bounded(p,3).unwrap(),b"new");
        let dir=root.join("blocked"); std::fs::create_dir(&dir).unwrap(); std::fs::write(dir.join("keep"),b"old").unwrap();
        assert!(write_atomic(dir.to_str().unwrap(),b"secret").is_err()); assert!(dir.join("keep").exists()); std::fs::remove_dir_all(root).unwrap();
    }
}
