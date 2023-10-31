use crate::bls::Fr;

const PRIMITIVE_ROOT_OF_UNITY: u64 = 7;

fn primitive_root_of_unity<const ORDER: usize>() -> Fr {
    let order = Fr::from(ORDER as u64);

    let power = Fr::MAX / order;
    let primitive = Fr::from(PRIMITIVE_ROOT_OF_UNITY);

    primitive.pow(power)
}

pub fn roots_of_unity<const ORDER: usize>() -> [Fr; ORDER] {
    let mut roots = [Fr::default(); ORDER];

    // TODO: panic for N == 0 (?)

    let primitive = primitive_root_of_unity::<ORDER>();
    let mut current = Fr::ONE;
    for power in 0..ORDER {
        roots[power] = current;
        current = current * primitive;
    }

    roots
}

/// # Panics
///
/// This function will panic if `N` is not a power of 2.
pub fn bit_reversal_permutation<const N: usize, T>(elements: &[T; N]) -> Box<[T; N]>
where
    T: Default + Copy,
{
    assert!(N.is_power_of_two());
    let log = N.ilog2() as usize;

    let mut permutation = Box::new([T::default(); N]);
    for i in 0..N {
        // TODO: the below code is quite inefficient
        let binary = format!("{i:b}");
        let mut reversed: String = binary.chars().rev().collect();
        while reversed.len() < log {
            reversed.push('0');
        }
        let reversed = usize::from_str_radix(&reversed, 2).unwrap();
        permutation[i] = elements[reversed];
    }

    permutation
}

#[cfg(test)]
mod tests {
    use super::Fr;

    #[test]
    fn bit_reversal_permutation() {
        const N: usize = 1 << 10;
        let mut elements: [u16; N] = [0; N];
        for element in &mut elements {
            *element = rand::random();
        }

        // since the permutation is an involution, the double application should be equal to the identity function
        let permuted = super::bit_reversal_permutation(&elements);
        let identity = super::bit_reversal_permutation(&permuted);

        for i in 0..N {
            assert_eq!(identity[i], elements[i]);
        }
    }

    #[test]
    #[should_panic]
    fn bit_reversal_permutation_non_power_of_two() {
        const N: usize = (1 << 10) - 1;
        let elements: [u16; N] = [0; N];
        super::bit_reversal_permutation(&elements);
    }

    #[test]
    fn primitive_root_of_unity() {
        let primitive = super::primitive_root_of_unity::<4096>();
        let primitive_inv = primitive.pow(Fr::from(4095));
        assert_eq!(primitive * primitive_inv, Fr::ONE);
    }
}
