use std::collections::{
    LinkedList, VecDeque,
    linked_list::{self, Iter},
};

/// A `RevisionVec` is a vector that stores pairs containing a key
/// and a sequence of values. Inserting a new value in the sequence
/// associated to an existing key prepends this value to the sequence.
///
/// Vec [
///     0: key -> a" -> a' -> a
///     1: key -> b
///     2: key -> c' -> c
/// ]
///
/// Insertions are only allowed at the front of the linked list.
/// Deletions can only happen at the end of the linked list.
///
/// This guarantees that the entry versions are always ordered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionVec<K, T> {
    chains: Vec<(K, LinkedList<T>)>,
}

pub struct RevisionIterator<'a, K, T> {
    ks: Vec<&'a K>,
    ls: Vec<Iter<'a, T>>,
}

impl<'a, K, T> Iterator for RevisionIterator<'a, K, T> {
    type Item = Vec<(&'a K, &'a T)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ks
            .iter()
            .zip(self.ls.iter_mut())
            .map(|(k, it)| it.next().map(|t| (*k, t)))
            .collect()
    }
}

impl<K, T> Default for RevisionVec<K, T> {
    fn default() -> Self {
        Self { chains: Default::default() }
    }
}

impl<K, T> RevisionVec<K, T> {
    #[must_use]
    pub fn new() -> Self {
        Self { chains: Vec::new() }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { chains: Vec::with_capacity(capacity) }
    }

    /// Returns the number of chains stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Returns the total number of elements stored.
    #[must_use]
    pub fn count_elements(&self) -> usize {
        self.chains.iter().map(|(_, chain)| chain.len()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// Creates and insert a new chain with a single value.
    pub fn create_chain_with_single_value(&mut self, key: K, val: T) {
        // Be aware that inserting a value for a key that is already associated to a
        // chain breaks the CoverCrypt scheme as two chains will exist for the same key.

        let mut new_chain = LinkedList::new();
        new_chain.push_front(val);
        self.chains.push((key, new_chain));
    }

    /// Inserts a new chain with a corresponding key.
    pub fn insert_new_chain(&mut self, key: K, new_chain: LinkedList<T>) {
        // Be aware that inserting a new chain for a key that is already associated to a
        // chain breaks the CoverCrypt scheme as two chains will exist for the same key.

        if !new_chain.is_empty() {
            self.chains.push((key, new_chain));
        }
    }

    pub fn clear(&mut self) {
        self.chains.clear();
    }

    /// Retains only the elements with a key validating the given predicate.
    pub fn retain(&mut self, f: impl Fn(&K) -> bool) {
        self.chains.retain(|(key, _)| f(key));
    }

    /// Returns an iterator over each key-chains pair
    #[allow(clippy::map_identity)] // unpack &(x, y) to (&x, &y)
    pub fn iter(&self) -> impl Iterator<Item = (&K, &LinkedList<T>)> {
        self.chains.iter().map(|(key, chain)| (key, chain))
    }

    /// Returns an iterator over each key-chains pair that allow modifying chain
    #[allow(clippy::map_identity)] // unpack &mut (x, y) to (&x, &mut y)
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&mut K, &mut LinkedList<T>)> {
        self.chains.iter_mut().map(|(key, chain)| (key, chain))
        // self.chains.iter_mut().map(|(key, chain)| (key, chain))
    }

    /// Iterates through all versions of all entries in a depth-first manner.
    /// Returns the key and value for each entry.
    pub fn flat_iter(&self) -> impl Iterator<Item = (&K, &T)> {
        self.chains
            .iter()
            .flat_map(|(key, chain)| chain.iter().map(move |val| (key, val)))
    }

    pub fn revisions(&self) -> impl Iterator<Item = Vec<(&K, &T)>> {
        let (ks, ls) = self.chains.iter().map(|(k, l)| (k, l.iter())).unzip();
        RevisionIterator { ks, ls }
    }

    /// Iterates through all versions of all entry in a breadth-first manner.
    #[must_use]
    pub fn bfs(&self) -> BfsQueue<T> {
        BfsQueue::new(self)
    }

    pub fn into_keys(self) -> impl Iterator<Item = K> {
        self.chains.into_iter().map(|(k, _)| k)
    }
}

impl<K, T> IntoIterator for RevisionVec<K, T> {
    type IntoIter = std::vec::IntoIter<(K, LinkedList<T>)>;
    type Item = (K, LinkedList<T>);

    fn into_iter(self) -> Self::IntoIter {
        self.chains.into_iter()
    }
}

/// Breadth-first search iterator for `RevisionVec`.
pub struct BfsQueue<'a, T> {
    queue: VecDeque<linked_list::Iter<'a, T>>,
}

impl<'a, T> BfsQueue<'a, T> {
    pub fn new<K>(revision_vec: &'a RevisionVec<K, T>) -> Self {
        // add all chain heads to the iterator queue
        Self {
            queue: revision_vec.chains.iter().map(|(_, chain)| chain.iter()).collect(),
        }
    }
}

impl<'a, T> Iterator for BfsQueue<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        // get first non-empty iterator in the queue
        while let Some(mut iterator) = self.queue.pop_front() {
            if let Some(element) = iterator.next() {
                // put back the iterator at the end of the queue
                self.queue.push_back(iterator);
                return Some(element);
            }
        }
        None
    }
}

impl<K, T> FromIterator<(K, LinkedList<T>)> for RevisionVec<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, LinkedList<T>)>>(iter: I) -> Self {
        Self { chains: iter.into_iter().collect() }
    }
}

impl<K, T> FromIterator<(K, T)> for RevisionVec<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, T)>>(iter: I) -> Self {
        Self {
            chains: iter.into_iter().map(|(k, v)| (k, LinkedList::from_iter([v]))).collect(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_revision_vec() {
        let mut revision_vec: RevisionVec<i32, String> = RevisionVec::new();
        assert!(revision_vec.is_empty());
        assert_eq!(revision_vec.len(), 0);

        // Insert
        revision_vec.insert_new_chain(
            1,
            vec!["a\"".to_string(), "a'".to_string(), "a".to_string()].into_iter().collect(),
        );
        revision_vec.create_chain_with_single_value(2, "b".to_string());
        revision_vec
            .insert_new_chain(3, vec!["c'".to_string(), "c".to_string()].into_iter().collect());

        assert_eq!(revision_vec.count_elements(), 6);
        assert_eq!(revision_vec.len(), 3);

        // Iterators
        let depth_iter: Vec<_> = revision_vec.flat_iter().collect();
        assert_eq!(
            depth_iter,
            vec![
                (&1, &"a\"".to_string()),
                (&1, &"a'".to_string()),
                (&1, &"a".to_string()),
                (&2, &"b".to_string()),
                (&3, &"c'".to_string()),
                (&3, &"c".to_string()),
            ]
        );

        let breadth_iter: Vec<_> = revision_vec.bfs().collect();
        assert_eq!(
            breadth_iter,
            vec![
                &"a\"".to_string(),
                &"b".to_string(),
                &"c'".to_string(),
                &"a'".to_string(),
                &"c".to_string(),
                &"a".to_string(),
            ]
        );

        // Retain
        revision_vec.retain(|key| key == &1);
        assert_eq!(revision_vec.count_elements(), 3);
        assert_eq!(revision_vec.len(), 1);

        // Clear
        revision_vec.clear();
        assert!(revision_vec.is_empty());
    }
}
