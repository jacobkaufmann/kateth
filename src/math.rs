use core::{marker::PhantomData, ops::Index};

use crate::bls::Fr;

const PRIMITIVE_ROOT_OF_UNITY: u64 = 7;

fn primitive_root_of_unity<const ORDER: usize>() -> Fr {
    let order = Fr::from(ORDER as u64);

    let power = Fr::MAX / order;
    let primitive = Fr::from(PRIMITIVE_ROOT_OF_UNITY);

    primitive.pow(&power)
}

pub fn roots_of_unity<const ORDER: usize>() -> [Fr; ORDER] {
    let mut roots = [Fr::default(); ORDER];

    // TODO: panic for N == 0 (?)

    let primitive = primitive_root_of_unity::<ORDER>();
    let mut current = Fr::ONE;
    for root in roots.iter_mut() {
        *root = current;
        current = current * primitive;
    }

    roots
}

pub struct BitReversalPermutation<T, S> {
    elements: S,
    phantom: PhantomData<T>,
}

impl<T, S> BitReversalPermutation<T, S>
where
    S: AsRef<[T]>,
{
    /// # Panics
    ///
    /// This function will panic if the length of `elements` is not a power of 2.
    pub fn new(elements: S) -> Self {
        assert!(elements.as_ref().len().is_power_of_two());
        Self {
            elements,
            phantom: PhantomData,
        }
    }

    pub(crate) fn iter(&self) -> BitReversalPermutationIter<T> {
        BitReversalPermutationIter {
            inner: self.elements.as_ref(),
            index: 0,
        }
    }
}

impl<T, S> Index<usize> for BitReversalPermutation<T, S>
where
    S: AsRef<[T]>,
{
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        let index = bit_reversal_permutation_index(index, self.elements.as_ref().len());
        &self.elements.as_ref()[index]
    }
}

pub struct BitReversalPermutationIter<'a, T> {
    inner: &'a [T],
    index: usize,
}

impl<'a, T> Iterator for BitReversalPermutationIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.inner.len() {
            return None;
        }

        let index = bit_reversal_permutation_index(self.index, self.inner.len());
        let next = &self.inner[index];

        self.index += 1;

        Some(next)
    }
}

fn bit_reversal_permutation_index(index: usize, len: usize) -> usize {
    index.reverse_bits() >> (usize::BITS - len.ilog2())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reversal_permutation() {
        const N: usize = 1 << 12;
        let mut elements: Vec<u16> = Vec::with_capacity(N);
        for _ in 0..N {
            elements.push(rand::random());
        }

        // since the permutation is an involution, the double application should be equal to the identity function
        let permutation = BitReversalPermutation::new(elements.clone());
        let mut permuted = Vec::with_capacity(N);
        for i in 0..N {
            permuted.push(permutation[i]);
        }
        let double_permutation = BitReversalPermutation::new(permuted);
        for i in 0..N {
            assert_eq!(double_permutation[i], elements[i]);
        }
    }

    #[test]
    #[should_panic]
    fn bit_reversal_permutation_non_power_of_two() {
        const N: usize = (1 << 12) - 1;
        let mut elements = vec![0u16; N];
        BitReversalPermutation::new(&mut elements);
    }

    #[test]
    fn primitive_root_of_unity() {
        let primitive = super::primitive_root_of_unity::<4096>();
        let primitive_inv = primitive.pow(&Fr::from(4095));
        assert_eq!(primitive * primitive_inv, Fr::ONE);
    }
}
