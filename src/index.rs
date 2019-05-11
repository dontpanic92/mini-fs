use crate::{EntryKind, File};

use std::borrow::Cow;
use std::collections::btree_map::{BTreeMap, Iter};
use std::collections::linked_list::LinkedList;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

struct DirNode<M> {
    name: Option<OsString>, // None for root
    files: BTreeMap<OsString, M>,
    dirs: BTreeMap<OsString, DirNode<M>>,
}

impl<M> DirNode<M> {
    fn new(name: Option<OsString>) -> Self {
        Self {
            name,
            files: BTreeMap::new(),
            dirs: BTreeMap::new(),
        }
    }
}

/// Directory index.
pub struct Index<M> {
    root: DirNode<M>,
}

/// Iterator over the entries of an index.
pub struct Entries<'a, M> {
    files: Option<Iter<'a, OsString, M>>,
    dirs: Option<Iter<'a, OsString, DirNode<M>>>,
}

impl<'a, M> Entries<'a, M> {
    fn next_file(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(ref mut iter) = self.files {
            iter.next().map(|(n, e)| Entry {
                name: n.as_os_str(),
                meta: Some(e),
                kind: EntryKind::File,
            })
        } else {
            None
        }
    }

    fn next_dir(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(ref mut iter) = self.dirs {
            iter.next().map(|(n, _)| Entry {
                name: n.as_os_str(),
                meta: None,
                kind: EntryKind::File,
            })
        } else {
            None
        }
    }
}

impl<'a, M> Iterator for Entries<'a, M> {
    type Item = Entry<'a, M>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_file().or_else(|| self.next_dir())
    }
}

/// Directory index entry
pub struct Entry<'a, M> {
    pub name: &'a OsStr,
    pub meta: Option<&'a M>,
    pub kind: EntryKind,
}

impl<M> Index<M> {
    pub fn new() -> Self {
        Self {
            root: DirNode::new(None),
        }
    }

    pub fn entries<P>(&self, path: P) -> Entries<M>
    where
        P: AsRef<Path>,
    {
        let path = normalize_path(path.as_ref()).to_path_buf();
        entries(path.into_iter().collect(), &self.root)
    }

    pub fn insert<P>(&mut self, path: P, meta: M)
    where
        P: Into<PathBuf>,
    {
        let path = normalize_path(&path.into()).to_path_buf();
        insert(path.into_iter().collect(), &mut self.root, meta)
    }

    pub fn get<P>(&self, path: P) -> Option<&M>
    where
        P: AsRef<Path>,
    {
        let path = normalize_path(path.as_ref()).to_path_buf();
        get(path.into_iter().collect(), &self.root)
    }
}

fn entries<'a, M>(mut parts: LinkedList<&OsStr>, node: &'a DirNode<M>) -> Entries<'a, M> {
    let f0 = parts.pop_front();
    match (f0, parts.front()) {
        (None, _) => Entries {
            files: None,
            dirs: None,
        },
        (Some(dir), None) => {
            if let Some(node) = node.dirs.get(dir) {
                Entries {
                    files: Some(node.files.iter()),
                    dirs: Some(node.dirs.iter()),
                }
            } else {
                Entries {
                    files: None,
                    dirs: None,
                }
            }
        }
        (Some(dir), Some(_)) => {
            if let Some(node) = node.dirs.get(dir) {
                entries(parts, node)
            } else {
                Entries {
                    files: Some(node.files.iter()),
                    dirs: Some(node.dirs.iter()),
                }
            }
        }
    }
}

fn insert<M>(mut parts: LinkedList<&OsStr>, node: &mut DirNode<M>, meta: M) {
    //panic!("{:?}", parts);
    let f0 = parts.pop_front();
    match (f0, parts.front()) {
        (None, _) => {}
        (Some(file), None) => {
            node.files.insert(file.to_os_string(), meta);
        }
        (Some(dir), Some(_)) => {
            if let Some(dir) = node.dirs.get_mut(dir) {
                insert(parts, dir, meta)
            } else {
                let name = dir.to_os_string();
                let mut new_node = DirNode::new(Some(name.clone()));
                insert(parts, &mut new_node, meta);
                node.dirs.insert(name, new_node);
            }
        }
    }
}

fn get<'a, M>(mut parts: LinkedList<&OsStr>, node: &'a DirNode<M>) -> Option<&'a M> {
    let f0 = parts.pop_front();
    match (f0, parts.front()) {
        (None, _) => None,
        (Some(file), None) => node.files.get(file),
        (Some(dir), Some(_)) => {
            if let Some(dir) = node.dirs.get(dir) {
                get(parts, dir)
            } else {
                None
            }
        }
    }
}

/// Normalizes path by removing references to the parent (`..`) and the current
/// (`.`) directory.
///
/// ```
/// use mini_fs::index::normalize_path;
/// use std::path::Path;
///
/// assert_eq!(Path::new("/"), normalize_path(Path::new("/a/b/c/../../..")),);
/// assert_eq!(Path::new("foo"), normalize_path(Path::new("./foo")),);
/// ```
pub fn normalize_path(path: &Path) -> Cow<Path> {
    use std::path::Component::*;
    if path.components().any(|c| match c {
        CurDir | ParentDir => true,
        _ => false,
    }) {
        let mut normal = PathBuf::new();
        for comp in path.components() {
            match comp {
                CurDir => {}
                ParentDir => {
                    normal.pop();
                }
                Normal(n) => normal.push(n),
                RootDir => normal.push("/"),
                _ => {}
            }
        }
        Cow::Owned(normal)
    } else {
        Cow::Borrowed(path)
    }
}
