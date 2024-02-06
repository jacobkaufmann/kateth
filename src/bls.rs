use std::{
    mem::MaybeUninit,
    ops::{Add, Div, Mul, Neg, Shl, ShlAssign, Shr, ShrAssign, Sub},
};

use alloy_primitives::{FixedBytes, U256};
use blst::{
    blst_bendian_from_scalar, blst_final_exp, blst_fp, blst_fp12, blst_fp12_is_one, blst_fp12_mul,
    blst_fr, blst_fr_add, blst_fr_cneg, blst_fr_eucl_inverse, blst_fr_from_scalar,
    blst_fr_from_uint64, blst_fr_lshift, blst_fr_mul, blst_fr_rshift, blst_fr_sub,
    blst_miller_loop, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_cneg,
    blst_p1_compress, blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine,
    blst_p2, blst_p2_add, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_deserialize,
    blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_scalar, blst_scalar_fr_check,
    blst_scalar_from_bendian, blst_scalar_from_fr, blst_scalar_from_uint64, blst_sha256,
    blst_uint64_from_fr, BLS12_381_G2, BLS12_381_NEG_G1, BLS12_381_NEG_G2, BLST_ERROR,
};

#[derive(Clone, Copy, Debug)]
pub enum FiniteFieldError {
    InvalidEncoding,
    NotInFiniteField,
}

#[derive(Clone, Copy, Debug)]
pub enum ECGroupError {
    InvalidEncoding,
    NotInGroup,
    NotOnCurve,
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    FiniteField(FiniteFieldError),
    ECGroup(ECGroupError),
}

impl From<FiniteFieldError> for Error {
    fn from(err: FiniteFieldError) -> Self {
        Self::FiniteField(err)
    }
}

impl From<ECGroupError> for Error {
    fn from(err: ECGroupError) -> Self {
        Self::ECGroup(err)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Scalar {
    element: blst_scalar,
}

impl Scalar {
    pub const BITS: usize = 256;
    pub const BYTES: usize = Self::BITS / 8;

    pub fn from_be_slice(bytes: impl AsRef<[u8]>) -> Option<Self> {
        if bytes.as_ref().len() != Self::BYTES {
            return None;
        }

        let mut out = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_bendian(out.as_mut_ptr(), bytes.as_ref().as_ptr());
            Some(Self {
                element: out.assume_init(),
            })
        }
    }

    pub fn to_be_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0; Self::BYTES];
        unsafe {
            blst_bendian_from_scalar(out.as_mut_ptr(), &self.element);
        }
        out
    }
}

impl From<u64> for Scalar {
    fn from(element: u64) -> Self {
        let element = [element, 0, 0, 0];
        let mut out = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_uint64(out.as_mut_ptr(), element.as_ptr());
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl From<&Fr> for Scalar {
    fn from(element: &Fr) -> Self {
        let mut out = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_fr(out.as_mut_ptr(), &element.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl AsRef<blst_scalar> for Scalar {
    fn as_ref(&self) -> &blst_scalar {
        &self.element
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Fr {
    element: blst_fr,
}

impl Fr {
    pub const ZERO: Self = Self {
        element: blst_fr { l: [0, 0, 0, 0] },
    };
    pub const ONE: Self = Self {
        element: blst_fr {
            l: [
                0x00000001fffffffe,
                0x5884b7fa00034802,
                0x998c4fefecbc4ff5,
                0x1824b159acc5056f,
            ],
        },
    };
    pub const MODULUS: Scalar = Scalar {
        element: blst_scalar {
            b: [
                1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9,
                8, 216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
            ],
        },
    };
    pub const MAX: Self = Self {
        element: blst_fr {
            l: [
                18446744060824649731,
                18102478225614246908,
                11073656695919314959,
                6613806504683796440,
            ],
        },
    };
    pub const BITS: usize = 256;
    pub const BYTES: usize = Self::BITS / 8;

    pub fn from_scalar(scalar: &Scalar) -> Option<Self> {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_scalar_fr_check(&scalar.element).then(|| {
                blst_fr_from_scalar(out.as_mut_ptr(), &scalar.element);
                Self {
                    element: out.assume_init(),
                }
            })
        }
    }

    pub fn from_be_bytes(bytes: impl AsRef<[u8; Self::BYTES]>) -> Option<Self> {
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_bendian(scalar.as_mut_ptr(), bytes.as_ref().as_ptr());
            Self::from_scalar(&Scalar {
                element: scalar.assume_init(),
            })
        }
    }

    pub fn from_be_slice(bytes: impl AsRef<[u8]>) -> Result<Self, FiniteFieldError> {
        let scalar =
            Scalar::from_be_slice(bytes.as_ref()).ok_or(FiniteFieldError::InvalidEncoding)?;
        let element = Self::from_scalar(&scalar).ok_or(FiniteFieldError::NotInFiniteField)?;
        Ok(element)
    }

    pub fn as_u64(&self) -> u64 {
        let mut out = [0, 0, 0, 0];
        unsafe {
            blst_uint64_from_fr(out.as_mut_ptr(), &self.element);
        }
        out[0]
    }

    pub fn pow(&self, power: &Self) -> Self {
        let mut power = *power;

        let mut out = *self;
        let mut tmp = Self::ONE;
        while power != Self::ONE && power != Self::ZERO {
            // remaining power odd
            if power.is_odd() {
                tmp = out * tmp;
                power = power - Self::ONE;
            }

            out = out * out;
            power >>= 1;
        }

        out = out * tmp;
        out
    }

    pub(crate) fn hash_to(data: impl AsRef<[u8]>) -> Self {
        let mut hash = [0; Self::BYTES];
        unsafe {
            blst_sha256(
                hash.as_mut_ptr(),
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            );
        }

        let modulus = U256::from_be_bytes(Self::MODULUS.to_be_bytes());
        let hash = U256::from_be_bytes(hash);
        let hash = hash.reduce_mod(modulus);

        let hash: [u8; Self::BYTES] = hash.to_be_bytes();
        let hash = FixedBytes::from(hash);

        Self::from_be_bytes(hash).unwrap()
    }

    fn is_odd(&self) -> bool {
        let mut scalar = blst_scalar::default();
        let mut bendian = [0; Self::BYTES];
        unsafe {
            blst_scalar_from_fr(&mut scalar, &self.element);
            blst_bendian_from_scalar(bendian.as_mut_ptr(), &scalar);
        }
        bendian[Self::BYTES - 1] & 0b00000001 == 1
    }
}

impl AsRef<blst_fr> for Fr {
    fn as_ref(&self) -> &blst_fr {
        &self.element
    }
}

impl From<u64> for Fr {
    fn from(element: u64) -> Self {
        let element = [element, 0, 0, 0];
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_from_uint64(out.as_mut_ptr(), element.as_ptr());
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Add for Fr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_add(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Sub for Fr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_sub(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Fr> for &Fr {
    type Output = Fr;

    fn mul(self, rhs: &Fr) -> Self::Output {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_mul(out.as_mut_ptr(), &self.element, &rhs.element);
            Fr {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Self> for Fr {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &Self) -> Self::Output {
        &self * rhs
    }
}

impl Mul for Fr {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl Div for Fr {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        assert_ne!(rhs, Fr::ZERO, "division by zero in finite field Fr");
        let mut inv = MaybeUninit::<blst_fr>::uninit();
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_eucl_inverse(inv.as_mut_ptr(), &rhs.element);
            blst_fr_mul(out.as_mut_ptr(), &self.element, inv.as_ptr());
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Neg for Fr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_cneg(out.as_mut_ptr(), &self.element, true);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl ShlAssign<usize> for Fr {
    fn shl_assign(&mut self, rhs: usize) {
        unsafe {
            blst_fr_lshift(&mut self.element, &self.element, rhs);
        }
    }
}

impl Shl<usize> for Fr {
    type Output = Fr;

    fn shl(mut self, rhs: usize) -> Self::Output {
        self <<= rhs;
        self
    }
}

impl ShrAssign<usize> for Fr {
    fn shr_assign(&mut self, rhs: usize) {
        unsafe {
            blst_fr_rshift(&mut self.element, &self.element, rhs);
        }
    }
}

impl Shr<usize> for Fr {
    type Output = Fr;

    fn shr(mut self, rhs: usize) -> Self::Output {
        self >>= rhs;
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct P1 {
    element: blst_p1,
}

impl P1 {
    pub const INF: Self = Self {
        element: blst_p1 {
            x: blst_fp {
                l: [0, 0, 0, 0, 0, 0],
            },
            y: blst_fp {
                l: [0, 0, 0, 0, 0, 0],
            },
            z: blst_fp {
                l: [0, 0, 0, 0, 0, 0],
            },
        },
    };
    pub const BITS: usize = 384;
    pub const BYTES: usize = Self::BITS / 8;

    pub fn deserialize(bytes: impl AsRef<[u8; Self::BYTES]>) -> Result<Self, ECGroupError> {
        let mut affine = MaybeUninit::<blst_p1_affine>::uninit();
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            // NOTE: deserialize performs a curve check but not a subgroup check. if that changes,
            // then we should encounter `unreachable` for `BLST_POINT_NOT_IN_GROUP` in tests.
            match blst_p1_deserialize(affine.as_mut_ptr(), bytes.as_ref().as_ptr()) {
                BLST_ERROR::BLST_SUCCESS => {}
                BLST_ERROR::BLST_BAD_ENCODING => return Err(ECGroupError::InvalidEncoding),
                BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(ECGroupError::NotOnCurve),
                other => unreachable!("{other:?}"),
            }
            if !blst_p1_affine_in_g1(affine.as_ptr()) {
                return Err(ECGroupError::NotInGroup);
            }

            blst_p1_from_affine(out.as_mut_ptr(), affine.as_ptr());
            Ok(Self {
                element: out.assume_init(),
            })
        }
    }

    pub fn serialize(&self) -> [u8; Self::BYTES] {
        let mut out = [0; Self::BYTES];
        unsafe {
            blst_p1_compress(out.as_mut_ptr(), &self.element);
        }
        out
    }

    // TODO: optimize w/ pippenger
    pub fn lincomb<'a>(terms: impl Iterator<Item = (&'a Self, &'a Fr)>) -> Self {
        let mut lincomb = Self::INF;
        for (point, scalar) in terms {
            lincomb = lincomb + (point * scalar);
        }

        lincomb
    }

    // TODO: optimize w/ pippenger
    // TODO: unify with `P1::lincomb`
    pub fn lincomb_owned(terms: impl Iterator<Item = (Self, Fr)>) -> Self {
        let mut lincomb = Self::INF;
        for (point, scalar) in terms {
            lincomb = lincomb + (point * scalar);
        }

        lincomb
    }

    // TODO: make available as `const`
    pub fn neg_generator() -> Self {
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            blst_p1_from_affine(out.as_mut_ptr(), &BLS12_381_NEG_G1);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl AsRef<blst_p1> for P1 {
    fn as_ref(&self) -> &blst_p1 {
        &self.element
    }
}

impl Add for P1 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            blst_p1_add(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Add<&Self> for P1 {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            blst_p1_add(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Fr> for &P1 {
    type Output = P1;

    fn mul(self, rhs: &Fr) -> Self::Output {
        let mut scalar = blst_scalar::default();
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.element);
            blst_p1_mult(out.as_mut_ptr(), &self.element, scalar.b.as_ptr(), 255);
            P1 {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Fr> for P1 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &Fr) -> Self::Output {
        &self * rhs
    }
}

impl Mul<Fr> for P1 {
    type Output = Self;

    fn mul(self, rhs: Fr) -> Self::Output {
        self * &rhs
    }
}

impl Neg for P1 {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        unsafe {
            blst_p1_cneg(&mut self.element, true);
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct P2 {
    element: blst_p2,
}

impl P2 {
    pub const BITS: usize = 768;
    pub const BYTES: usize = Self::BITS / 8;

    pub fn deserialize(bytes: impl AsRef<[u8; Self::BYTES]>) -> Result<Self, ECGroupError> {
        let mut affine = MaybeUninit::<blst_p2_affine>::uninit();
        let mut out = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            // NOTE: deserialize performs a curve check but not a subgroup check. if that changes,
            // then we should encounter `unreachable` for `BLST_POINT_NOT_IN_GROUP` in tests.
            match blst_p2_deserialize(affine.as_mut_ptr(), bytes.as_ref().as_ptr()) {
                BLST_ERROR::BLST_SUCCESS => {}
                BLST_ERROR::BLST_BAD_ENCODING => return Err(ECGroupError::InvalidEncoding),
                BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(ECGroupError::NotOnCurve),
                other => unreachable!("{other:?}"),
            }
            if !blst_p2_affine_in_g2(affine.as_ptr()) {
                return Err(ECGroupError::NotInGroup);
            }

            blst_p2_from_affine(out.as_mut_ptr(), affine.as_ptr());
            Ok(Self {
                element: out.assume_init(),
            })
        }
    }

    // TODO: make available as `const`
    pub fn generator() -> Self {
        let mut out = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            blst_p2_from_affine(out.as_mut_ptr(), &BLS12_381_G2);
            Self {
                element: out.assume_init(),
            }
        }
    }

    // TODO: make available as `const`
    pub fn neg_generator() -> Self {
        let mut out = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            blst_p2_from_affine(out.as_mut_ptr(), &BLS12_381_NEG_G2);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Add for P2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            blst_p2_add(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Fr> for &P2 {
    type Output = P2;

    fn mul(self, rhs: &Fr) -> Self::Output {
        let mut scalar = blst_scalar::default();
        let mut out = MaybeUninit::<blst_p2>::uninit();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.element);
            blst_p2_mult(out.as_mut_ptr(), &self.element, scalar.b.as_ptr(), 255);
            P2 {
                element: out.assume_init(),
            }
        }
    }
}

impl Mul<&Fr> for P2 {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, rhs: &Fr) -> Self::Output {
        &self * rhs
    }
}

impl Mul<Fr> for P2 {
    type Output = Self;

    fn mul(self, rhs: Fr) -> Self::Output {
        self * &rhs
    }
}

pub fn verify_pairings((a1, a2): (P1, P2), (b1, b2): (P1, P2)) -> bool {
    let mut a1_neg_affine = MaybeUninit::<blst_p1_affine>::uninit();
    let mut a2_affine = MaybeUninit::<blst_p2_affine>::uninit();

    let mut b1_affine = MaybeUninit::<blst_p1_affine>::uninit();
    let mut b2_affine = MaybeUninit::<blst_p2_affine>::uninit();

    let mut e1 = MaybeUninit::<blst_fp12>::uninit();
    let mut e2 = MaybeUninit::<blst_fp12>::uninit();
    let mut prod = MaybeUninit::<blst_fp12>::uninit();
    let mut exp = MaybeUninit::<blst_fp12>::uninit();

    unsafe {
        blst_p1_to_affine(a1_neg_affine.as_mut_ptr(), &a1.neg().element);
        blst_p2_to_affine(a2_affine.as_mut_ptr(), &a2.element);

        blst_p1_to_affine(b1_affine.as_mut_ptr(), &b1.element);
        blst_p2_to_affine(b2_affine.as_mut_ptr(), &b2.element);

        blst_miller_loop(e1.as_mut_ptr(), a2_affine.as_ptr(), a1_neg_affine.as_ptr());
        blst_miller_loop(e2.as_mut_ptr(), b2_affine.as_ptr(), b1_affine.as_ptr());

        blst_fp12_mul(prod.as_mut_ptr(), e1.as_ptr(), e2.as_ptr());
        blst_final_exp(exp.as_mut_ptr(), prod.as_ptr());
        blst_fp12_is_one(exp.as_ptr())
    }
}

impl AsRef<blst_p2> for P2 {
    fn as_ref(&self) -> &blst_p2 {
        &self.element
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_one() {
        assert_eq!(Fr::ONE.as_u64(), 1);
    }

    #[test]
    fn fr_max() {
        assert_eq!(Fr::MAX + Fr::ONE, Fr::ZERO);
    }
}
