use crate::{
    bls::{Fr, Scalar, P1},
    math::{self, BitReversalPermutation},
};

use super::{proof::Proof, setup::Setup};

pub(crate) struct Polynomial<const N: usize>(pub(crate) Box<[Fr; N]>);

impl<const N: usize> Polynomial<N> {
    /// evaluates the polynomial at `point`.
    pub(crate) fn evaluate(&self, point: Fr) -> Fr {
        let roots = math::roots_of_unity::<N>();
        let roots = BitReversalPermutation::new(roots);

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
        let term = (point.pow(Fr::from(N as u64)) - Fr::ONE) / Fr::from(N as u64);
        eval * term
    }

    /// returns a `Proof` for the evaluation of the polynomial at `point`.
    pub(crate) fn prove<const G1: usize, const G2: usize>(
        &self,
        point: Fr,
        setup: impl AsRef<Setup<G1, G2>>,
    ) -> (Fr, Proof) {
        assert_eq!(G1, N);
        let roots = math::roots_of_unity::<N>();
        let roots = BitReversalPermutation::new(roots);

        let eval = self.evaluate(point);

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
            quotient_poly.push(Scalar::from(quotient));
        }

        let g1_lagrange = BitReversalPermutation::new(setup.as_ref().g1_lagrange.as_slice());
        let lincomb = P1::lincomb(g1_lagrange.iter().zip(quotient_poly));

        (eval, Proof(lincomb))
    }
}
