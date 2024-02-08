use crate::{
    bls::{Fr, P1},
    math::BitReversalPermutation,
};

use super::{setup::Setup, Proof};

#[derive(Clone, Debug)]
pub(crate) struct Polynomial<'a, const N: usize>(pub(crate) &'a [Fr; N]);

impl<'a, const N: usize> Polynomial<'a, N> {
    /// evaluates the polynomial at `point`.
    pub(crate) fn evaluate<const G2: usize>(&self, point: Fr, setup: &Setup<N, G2>) -> Fr {
        let roots = BitReversalPermutation::new(setup.roots_of_unity.as_slice());

        // if `point` is a root of a unity, then we have the evaluation available
        for i in 0..N {
            if point == roots[i] {
                return self.0[i];
            }
        }

        let mut eval = Fr::ZERO;

        // barycentric evaluation summation
        for i in 0..N {
            let numer = self.0[i] * roots[i];
            let denom = point - roots[i];
            let term = numer / denom;
            eval = eval + term;
        }

        // barycentric evaluation scalar multiplication
        let term = (point.pow(&Fr::from(N as u64)) - Fr::ONE) / Fr::from(N as u64);
        eval * term
    }

    /// returns a `Proof` for the evaluation of the polynomial at `point`.
    pub(crate) fn prove<const G2: usize>(&self, point: Fr, setup: &Setup<N, G2>) -> (Fr, Proof) {
        let roots = BitReversalPermutation::new(setup.roots_of_unity.as_slice());

        let eval = self.evaluate(point, setup);

        // compute the quotient polynomial
        //
        // TODO: parallelize (e.g. rayon)
        let mut quotient_poly = Vec::with_capacity(N);
        for i in 0..N {
            let numer = self.0[i] - eval;
            let denom = roots[i] - point;
            let quotient = if denom != Fr::ZERO {
                numer / denom
            } else {
                let mut quotient = Fr::ZERO;
                for j in 0..N {
                    if j == i {
                        continue;
                    }

                    let coefficient = self.0[j] - eval;
                    let numer = coefficient * roots[j];
                    let denom = (roots[i] * roots[i]) - (roots[i] * roots[j]);
                    let term = numer / denom;
                    quotient = quotient + term;
                }
                quotient
            };
            quotient_poly.push(quotient);
        }

        let g1_lagrange = BitReversalPermutation::new(setup.g1_lagrange.as_slice());
        let lincomb = P1::lincomb(g1_lagrange.iter().zip(quotient_poly.iter()));

        (eval, lincomb)
    }
}
