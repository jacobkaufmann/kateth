use core::fmt::Debug;

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

/// # Panics
///
/// This function will panic if the length of `elements` is not a power of 2.
pub(crate) fn bit_reversal_permutation<T>(elements: impl AsRef<[T]>) -> Vec<T>
where
    T: Copy,
{
    let n = elements.as_ref().len();
    assert!(n.is_power_of_two());
    let mut brp = Vec::with_capacity(n);
    for i in 0..n {
        let index = bit_reversal_permutation_index(i, n);
        brp.push(elements.as_ref()[index]);
    }
    brp
}

/// # Panics
///
/// This function will panic if the length of `elements` is not equal to `N`.
///
/// This function will panic if the length of `elements` is not a power of 2.
pub(crate) fn bit_reversal_permutation_boxed_array<T, const N: usize>(
    elements: impl AsRef<[T]>,
) -> Box<[T; N]>
where
    T: Copy + Debug,
{
    assert_eq!(elements.as_ref().len(), N);
    assert!(N.is_power_of_two());

    let brp = bit_reversal_permutation(elements);

    // TODO: make sure the conversion does not cause a new allocation
    let brp: Box<[T; N]> = brp
        .try_into()
        .expect("infallible conversion to equal len boxed array");

    brp
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
        let permutation = super::bit_reversal_permutation(&elements);
        let mut permuted = Vec::with_capacity(N);
        for element in permutation.iter().take(N) {
            permuted.push(*element);
        }
        let double_permutation = super::bit_reversal_permutation(permuted);
        for i in 0..N {
            assert_eq!(double_permutation[i], elements[i]);
        }
    }

    #[test]
    #[should_panic]
    fn bit_reversal_permutation_non_power_of_two() {
        const N: usize = (1 << 12) - 1;
        let elements = vec![0u16; N];
        super::bit_reversal_permutation(elements);
    }

    #[test]
    fn primitive_root_of_unity() {
        let primitive = super::primitive_root_of_unity::<4096>();
        let primitive_inv = primitive.pow(&Fr::from(4095));
        assert_eq!(primitive * primitive_inv, Fr::ONE);
    }
}
