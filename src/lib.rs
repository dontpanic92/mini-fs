//! `mini-fs` is an extensible virtual filesystem for the application layer.
//!
//! Currently supported features include:
//!
//! - Access to the local (native) filesystem.
//! - In-memory filesystems.
//! - Read from tar, tar.gz, and zip archives.
//! - Filesystem overlays.
//!
//! ## Case sensitivity
//!
//! All implementations of [`Store`] from this crate use **case sensitive**¹
//! paths. However, you are free to implement custom stores where paths are case
//! insensitive.
//!
//! ¹ Except maybe [`LocalFs`], which uses [`std::fs`] internally and is subject
//! to the underlying OS.
//!
//! ## Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use mini_fs::prelude::*;
//! use mini_fs::{LocalFs, MiniFs, ZipFs};
//!
//! let gfx = LocalFs::new("./res/images");
//! let sfx = ZipFs::open("archive.zip")?;
//!
//! let assets = MiniFs::new().mount("/gfx", gfx).mount("/sfx", sfx);
//!
//! let root = MiniFs::new().mount("/assets", assets);
//!
//! let file = root.open("/assets/gfx/trash.gif")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security
//!
//! Don't use this crate in applications where security is a critical factor.
//! [`LocalFs`] in particular might be vulnerable to [directory traversal
//! attacks][dir], so it's best not to use it directly in a static file server,
//! for example.
//!
//! [`std::fs`]: https://doc.rust-lang.org/std/fs/index.html
//! [`Store`]: ./trait.Store.html
//! [`LocalFs`]: ./struct.LocalFs.html
//! [dir]: https://en.wikipedia.org/wiki/Directory_traversal_attack
// #![deny(warnings)]
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::{any::Any, collections::HashMap, ffi::OsString, path::Component};
use std::{
    collections::BTreeSet,
    io::{Cursor, Error, ErrorKind, Read, Result, Seek, SeekFrom},
};
use std::{env, fs};

pub use caseless::CaselessFs;
//pub use index::{Index, IndexEntries};
pub use store::{Entries, Entry, EntryKind, Store, StoreExt};
#[cfg(feature = "tar")]
pub use tar::TarFs;
#[cfg(feature = "zip")]
pub use zip::ZipFs;

include!("macros.rs");

pub mod caseless;
/// Directory index.
#[doc(hidden)]
pub mod index;
mod store;
/// Tar file storage.
#[cfg(feature = "tar")]
pub mod tar;
/// Zip file storage.
#[cfg(feature = "zip")]
pub mod zip;
/// Convenient library imports.
pub mod prelude {
    pub use crate::store::{Store, StoreExt};
}

impl_file! {
    /// File you can seek and read from.
    pub enum File {
        Local(fs::File),
        Ram(RamFile),
        #[cfg(feature = "zip")]
        Zip(zip::ZipFsFile),
        #[cfg(feature = "tar")]
        Tar(tar::TarFsFile),
        // External types are dynamic
        User(Box<dyn UserFile>),
    }
}

/// Custom file type.
pub trait UserFile: Any + Read + Seek + Send {}

impl<T: UserFile> From<T> for File {
    fn from(file: T) -> Self {
        File::User(Box::new(file))
    }
}

struct Mount {
    store: Box<dyn Store<File = File>>,
    priority: u32,
}

struct Folder {
    children: HashMap<OsString, Folder>,
    mounts: Vec<Mount>,
}

impl Folder {
    pub fn new() -> Self {
        Folder {
            children: HashMap::new(),
            mounts: vec![],
        }
    }
}

struct StoreCandidate<'a> {
    path: PathBuf,
    mount: &'a Mount,
    priority: u32,
}

/// Virtual filesystem.
pub struct MiniFs {
    root: Folder,
    case_sensitive: bool,
    next_priority: u32,
}

impl Store for MiniFs {
    type File = File;

    fn open_path(&self, path: &Path) -> Result<File> {
        let mut candidates = self.collect_candidate(path).0;
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        // let candidate = Self::choose_candidate(candidates.0);

        for candidate in candidates {
            let res = candidate.mount.store.open_path(&candidate.path);
            if res.is_ok() {
                return res;
            }
        }

        Err(Error::from(ErrorKind::NotFound))
    }

    fn entries_path(&self, path: &Path) -> Result<Entries> {
        let candidates = self.collect_candidate(path);
        // let candidate = Self::choose_candidate(candidates.0);

        struct PrioritizedEntry {
            priority: u32,
            entry: Entry,
        }

        let mut entries = HashMap::new();
        let mut insert_entry = |e: Entry, priority: u32| {
            entries
                .entry(e.name.to_ascii_lowercase())
                .and_modify(|pe: &mut PrioritizedEntry| {
                    if pe.priority < priority {
                        *pe = PrioritizedEntry {
                            priority,
                            entry: e.clone(),
                        };
                    }
                })
                .or_insert(PrioritizedEntry { priority, entry: e });
        };

        for candidate in &candidates.0 {
            let c_entries = candidate.mount.store.entries_path(&candidate.path);
            if let Ok(c_entries) = c_entries {
                for e in c_entries {
                    if let Ok(e) = e {
                        insert_entry(e, candidate.priority);
                    }
                }
            }
        }

        if candidates.1.is_some() {
            for child in candidates.1.unwrap().children.keys() {
                insert_entry(
                    Entry {
                        name: child.clone(),
                        kind: EntryKind::Dir,
                    },
                    0,
                );
            }
        }

        if entries.is_empty() {
            Err(Error::from(ErrorKind::NotFound))
        } else {
            let entries = entries.into_values().map(|v| Ok(v.entry)).collect();
            Ok(Entries::new(VecIter::new(entries)))
        }
    }
}

impl MiniFs {
    pub fn new(case_sensitive: bool) -> Self {
        Self {
            root: Folder::new(),
            case_sensitive,
            next_priority: 1,
        }
    }

    pub fn mount<P, S, T>(mut self, path: P, store: S) -> Self
    where
        P: Into<PathBuf>,
        S: Store<File = T> + 'static,
        T: Into<File>,
    {
        let priority = self.next_priority;
        self.next_priority += 1;

        let dst = self.make_dir(path.into());
        dst.mounts.push(Mount {
            store: Box::new(store::MapFile::new(store, |file: T| file.into())),
            priority,
        });

        self
    }

    pub fn umount<P>(&mut self, path: P) -> Option<Box<dyn Store<File = File>>>
    where
        P: AsRef<Path>,
    {
        self.goto_dir(path.as_ref())
            .and_then(|f| f.mounts.pop().and_then(|m| Some(m.store)))
    }

    fn choose_candidate(candidates: Vec<StoreCandidate>) -> Option<StoreCandidate> {
        candidates
            .into_iter()
            .fold(None, |acc: Option<StoreCandidate>, cur| {
                if acc.is_none() || acc.as_ref().unwrap().priority < cur.priority {
                    Some(cur)
                } else {
                    acc
                }
            })
    }

    fn collect_candidate<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> (Vec<StoreCandidate<'_>>, Option<&Folder>) {
        let case_sensitive = self.case_sensitive;
        let mut candidates = vec![];
        let acc = path
            .as_ref()
            .components()
            .map(|c| Some(c))
            .chain(vec![None].into_iter())
            .skip(1)
            .fold(Some((&self.root, PathBuf::from("/"))), |acc, component| {
                acc.and_then(|(current, prefix)| {
                    current.mounts.iter().for_each(|m| {
                        candidates.push(StoreCandidate {
                            path: path
                                .as_ref()
                                .strip_prefix_ex(&prefix, self.case_sensitive)
                                .unwrap()
                                .to_owned(),
                            mount: &m,
                            priority: m.priority,
                        })
                    });

                    if let Some(component) = component {
                        let name = Self::get_component_name(&component, case_sensitive);
                        if let Some(child) = current.children.get(&name) {
                            let p = prefix.join(&name);
                            return Some((child, p));
                        } else {
                            return None;
                        }
                    }

                    Some((current, prefix))
                })
            });

        (candidates, acc.map(|(f, _)| f))
    }

    fn make_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Folder {
        let case_sensitive = self.case_sensitive;
        path.as_ref()
            .components()
            .fold(&mut self.root, |parent, component| {
                if component == Component::RootDir {
                    return parent;
                }

                let name = Self::get_component_name(&component, case_sensitive);

                if !parent.children.contains_key(&name) {
                    parent.children.insert(name.clone(), Folder::new());
                }

                parent.children.get_mut(&name).unwrap()
            })
    }

    fn goto_dir<P: AsRef<Path>>(&mut self, path: P) -> Option<&mut Folder> {
        let case_sensitive = self.case_sensitive;
        path.as_ref()
            .components()
            .fold(Some(&mut self.root), |parent, component| {
                if component == Component::RootDir {
                    return parent;
                }

                parent.and_then(|p| {
                    let name = Self::get_component_name(&component, case_sensitive);
                    p.children.get_mut(&name)
                })
            })
    }

    fn get_component_name(component: &Component, case_sensitive: bool) -> OsString {
        let mut name = component.as_os_str().to_owned();
        if !case_sensitive {
            name = name.to_ascii_lowercase();
        }

        name
    }
}

pub struct VecIter {
    entries: Vec<std::io::Result<Entry>>,
    index: usize,
    set: BTreeSet<OsString>,
}

impl VecIter {
    pub fn new(entries: Vec<std::io::Result<Entry>>) -> Self {
        Self {
            entries,
            index: 0,
            set: BTreeSet::new(),
        }
    }
}

impl Iterator for VecIter {
    type Item = std::io::Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.index < self.entries.len() {
                let x = self.entries[self.index].as_ref();
                match x {
                    Err(e) => return Some(Err(std::io::Error::from(e.kind()))),
                    Ok(e) => {
                        if !self.set.contains(&e.name) {
                            self.set.insert(e.name.clone());
                            return Some(Ok(e.clone()));
                        }
                    }
                }

                self.index += 1;
            } else {
                return None;
            }
        }
    }
}

/// Native file store.
pub struct LocalFs {
    root: PathBuf,
}

impl Store for LocalFs {
    type File = fs::File;

    fn open_path(&self, path: &Path) -> Result<fs::File> {
        fs::OpenOptions::new()
            .create(false)
            .read(true)
            .write(false)
            .open(self.root.join(path))
    }

    fn entries_path(&self, path: &Path) -> Result<Entries> {
        // FIXME cloned because lifetimes.
        //let root = self.root.clone();

        let entries = fs::read_dir(self.root.join(path))?.map(move |ent| {
            let entry = ent?;
            let path = entry
                .path()
                .strip_prefix(&self.root)
                .map(Path::to_path_buf)
                .expect("Error striping path suffix.");
            let file_type = entry.file_type()?;

            // TODO synlinks
            let kind = if file_type.is_dir() {
                EntryKind::Dir
            } else if file_type.is_symlink() {
                EntryKind::File
            } else {
                EntryKind::File
            };

            Ok(Entry {
                name: path.into_os_string(),
                kind,
            })
        });

        Ok(Entries::new(entries))
    }
}

impl LocalFs {
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Self { root: root.into() }
    }

    /// Point to the current working directory.
    pub fn pwd() -> Result<Self> {
        Ok(Self::new(env::current_dir()?))
    }
}

/// In-memory file storage
pub struct RamFs {
    index: index::Index<Rc<[u8]>>,
}

/// In-memory file.
pub struct RamFile(Cursor<Rc<[u8]>>);

impl Read for RamFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for RamFile {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.0.seek(pos)
    }
}

impl Store for RamFs {
    type File = RamFile;

    fn open_path(&self, path: &Path) -> Result<Self::File> {
        match self.index.get(path) {
            Some(file) => Ok(RamFile(Cursor::new(Rc::clone(file)))),
            None => Err(Error::from(ErrorKind::NotFound)),
        }
    }

    fn entries_path(&self, path: &Path) -> Result<Entries> {
        Ok(Entries::new(self.index.entries(path).map(|ent| {
            Ok(Entry {
                name: ent.name.to_os_string(),
                kind: ent.kind,
            })
        })))
    }
}

impl RamFs {
    pub fn new() -> Self {
        Self {
            index: index::Index::new(),
        }
    }

    pub fn clear(&mut self) {
        self.index.clear();
    }

    pub fn rm<P: AsRef<Path>>(&mut self, path: P) -> Option<Rc<[u8]>> {
        self.index.remove(path)
    }

    pub fn touch<P, F>(&mut self, path: P, file: F)
    where
        P: Into<PathBuf>,
        F: Into<Rc<[u8]>>,
    {
        self.index.insert(path.into(), file.into());
    }

    pub fn index(self) -> Self {
        self
    }
}

#[derive(Debug)]
struct StripPrefixExError(());
trait StripPrefixEx {
    fn strip_prefix_ex<P>(
        &self,
        base: P,
        case_sensitivify: bool,
    ) -> std::result::Result<&Path, StripPrefixExError>
    where
        P: AsRef<Path>;
}

impl StripPrefixEx for Path {
    fn strip_prefix_ex<P>(
        &self,
        base: P,
        case_sensitivify: bool,
    ) -> std::result::Result<&Path, StripPrefixExError>
    where
        P: AsRef<Path>,
    {
        if case_sensitivify {
            self.strip_prefix(base).or(Err(StripPrefixExError(())))
        } else {
            _strip_prefix_case_insensitive(&self, base.as_ref())
        }
    }
}

fn _strip_prefix_case_insensitive<'a>(
    path: &'a Path,
    base: &Path,
) -> std::result::Result<&'a Path, StripPrefixExError> {
    iter_after_case_insensitive(path.components(), base.components())
        .map(|c| c.as_path())
        .ok_or(StripPrefixExError(()))
}

fn iter_after_case_insensitive<'a, 'b, I, J>(mut iter: I, mut prefix: J) -> Option<I>
where
    I: Iterator<Item = Component<'a>> + Clone,
    J: Iterator<Item = Component<'b>>,
{
    loop {
        let mut iter_next = iter.clone();
        match (iter_next.next(), prefix.next()) {
            (Some(ref x), Some(ref y)) if x.as_os_str().eq_ignore_ascii_case(y.as_os_str()) => (),
            (Some(_), Some(_)) => return None,
            (Some(_), None) => return Some(iter),
            (None, None) => return Some(iter),
            (None, Some(_)) => return None,
        }
        iter = iter_next;
    }
}
