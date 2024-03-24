use core::{
    cmp,
    mem::MaybeUninit,
    ops::{Add, Div, Mul, Neg, Shl, ShlAssign, Shr, ShrAssign, Sub},
    slice,
};

use blst::{
    blst_bendian_from_scalar, blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_fr,
    blst_fr_add, blst_fr_cneg, blst_fr_eucl_inverse, blst_fr_from_scalar, blst_fr_from_uint64,
    blst_fr_lshift, blst_fr_mul, blst_fr_rshift, blst_fr_sub, blst_lendian_from_scalar,
    blst_miller_loop, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_cneg,
    blst_p1_compress, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress,
    blst_p2, blst_p2_add, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_cneg, blst_p2_compress,
    blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress, blst_scalar,
    blst_scalar_fr_check, blst_scalar_from_bendian, blst_scalar_from_fr, blst_sha256,
    blst_uint64_from_fr, p1_affines, p2_affines, BLS12_381_G1, BLS12_381_G2, BLS12_381_NEG_G1,
    BLS12_381_NEG_G2, BLST_ERROR,
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

/// A data structure that can be serialized into the compressed format defined by Zcash.
///
/// github.com/zkcrypto/pairing/blob/34aa52b0f7bef705917252ea63e5a13fa01af551/src/bls12_381/README.md
pub trait Compress {
    /// The length in bytes of the compressed representation of `self`.
    const COMPRESSED: usize;

    /// Compresses `self` into `buf`.
    ///
    /// # Errors
    ///
    /// Compression will fail if the length of `buf` is less than `Self::COMPRESSED`.
    fn compress(&self, buf: impl AsMut<[u8]>) -> Result<(), &'static str>;
}

/// A data structure that can be deserialized from the compressed format defined by Zcash.
///
/// github.com/zkcrypto/pairing/blob/34aa52b0f7bef705917252ea63e5a13fa01af551/src/bls12_381/README.md
pub trait Decompress: Sized {
    /// The error that can occur upon decompression.
    type Error;

    /// Decompresses `compressed` into `Self`.
    fn decompress(compressed: impl AsRef<[u8]>) -> Result<Self, Self::Error>;
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

    pub(crate) fn from_blst_scalar(scalar: blst_scalar) -> Option<Self> {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_scalar_fr_check(&scalar).then(|| {
                blst_fr_from_scalar(out.as_mut_ptr(), &scalar);
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
            Self::from_blst_scalar(scalar.assume_init())
        }
    }

    pub fn from_be_slice(bytes: impl AsRef<[u8]>) -> Result<Self, FiniteFieldError> {
        if bytes.as_ref().len() != Self::BYTES {
            return Err(FiniteFieldError::InvalidEncoding);
        }
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_bendian(scalar.as_mut_ptr(), bytes.as_ref().as_ptr());
            Self::from_blst_scalar(scalar.assume_init()).ok_or(FiniteFieldError::NotInFiniteField)
        }
    }

    pub fn to_be_bytes(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_fr(scalar.as_mut_ptr(), &self.element);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), scalar.as_ptr());
        }
        bytes
    }

    pub fn to_le_bytes(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_fr(scalar.as_mut_ptr(), &self.element);
            blst_lendian_from_scalar(bytes.as_mut_ptr(), scalar.as_ptr());
        }
        bytes
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
        let mut out = MaybeUninit::<blst_fr>::uninit();
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        let mut hash = [0; Self::BYTES];
        unsafe {
            blst_sha256(
                hash.as_mut_ptr(),
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            );
            blst_scalar_from_bendian(scalar.as_mut_ptr(), hash.as_ptr());
            blst_fr_from_scalar(out.as_mut_ptr(), scalar.as_ptr());
            Self {
                element: out.assume_init(),
            }
        }
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

macro_rules! impl_group {
    (
        $p:ident,
        $gelt:ty,
        $affine:ty,
        $from_affine:ident,
        $to_affine:ident,
        $affines:ident,
        $gen:expr,
        $neg_gen:expr,
        $add:ident,
        $neg:ident,
        $mul:ident,
        $affine_in_group:ident,
        $compress:ident,
        $uncompress:ident,
        $COMPRESSED:expr
    ) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $p {
            element: $gelt,
        }

        impl $p {
            // TODO: make available as `const`
            pub fn generator() -> Self {
                let mut out = MaybeUninit::<$gelt>::uninit();
                unsafe {
                    $from_affine(out.as_mut_ptr(), &$gen);
                    Self::from(out.assume_init())
                }
            }

            // TODO: make available as `const`
            pub fn neg_generator() -> Self {
                let mut out = MaybeUninit::<$gelt>::uninit();
                unsafe {
                    $from_affine(out.as_mut_ptr(), &$neg_gen);
                    Self::from(out.assume_init())
                }
            }

            #[allow(dead_code)]
            pub fn lincomb(points: impl AsRef<[Self]>, scalars: impl AsRef<[Fr]>) -> Self {
                let n = cmp::min(points.as_ref().len(), scalars.as_ref().len());
                let mut lincomb = Self::default();
                for i in 0..n {
                    lincomb = lincomb + (points.as_ref()[i] * scalars.as_ref()[i]);
                }
                lincomb
            }

            #[allow(dead_code)]
            pub fn lincomb_pippenger(
                points: impl AsRef<[Self]>,
                scalars: impl AsRef<[Fr]>,
            ) -> Self {
                let n = cmp::min(points.as_ref().len(), scalars.as_ref().len());

                let points = unsafe {
                    // NOTE: we can perform the cast given `repr(transparent)` for the struct.
                    slice::from_raw_parts(points.as_ref().as_ptr() as *const $gelt, n)
                };
                let points = $affines::from(points);

                let scalar_iter = scalars.as_ref().iter().take(n);
                let mut scalars = Vec::with_capacity(n * Fr::BYTES);
                for scalar in scalar_iter.map(|scalar| scalar.to_le_bytes()) {
                    scalars.extend_from_slice(scalar.as_slice());
                }

                let lincomb = points.mult(&scalars, 255);

                Self { element: lincomb }
            }
        }

        impl From<$gelt> for $p {
            fn from(element: $gelt) -> Self {
                Self { element }
            }
        }

        impl AsRef<$gelt> for $p {
            fn as_ref(&self) -> &$gelt {
                &self.element
            }
        }

        impl Add for $p {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                let mut out = MaybeUninit::<$gelt>::uninit();
                unsafe {
                    $add(out.as_mut_ptr(), &self.element, &rhs.element);
                    Self {
                        element: out.assume_init(),
                    }
                }
            }
        }

        impl Neg for $p {
            type Output = Self;

            fn neg(mut self) -> Self::Output {
                unsafe {
                    $neg(&mut self.element, true);
                }
                self
            }
        }

        impl Mul<Fr> for $p {
            type Output = Self;

            fn mul(self, rhs: Fr) -> Self::Output {
                let mut scalar = blst_scalar::default();
                let mut out = MaybeUninit::<$gelt>::uninit();
                unsafe {
                    blst_scalar_from_fr(&mut scalar, &rhs.element);
                    $mul(out.as_mut_ptr(), &self.element, scalar.b.as_ptr(), 255);
                    $p::from(out.assume_init())
                }
            }
        }

        impl Compress for $p {
            const COMPRESSED: usize = $COMPRESSED;

            fn compress(&self, mut buf: impl AsMut<[u8]>) -> Result<(), &'static str> {
                if buf.as_mut().len() < Self::COMPRESSED {
                    return Err("insufficient buffer length");
                }
                unsafe {
                    $compress(buf.as_mut().as_mut_ptr(), &self.element);
                }
                Ok(())
            }
        }

        impl Decompress for $p {
            type Error = ECGroupError;

            fn decompress(compressed: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
                let mut affine = MaybeUninit::<$affine>::uninit();
                let mut out = MaybeUninit::<$gelt>::uninit();
                unsafe {
                    // NOTE: uncompress performs a curve check but not a subgroup check. if that changes,
                    // then we should encounter `unreachable` for `BLST_POINT_NOT_IN_GROUP` in tests.
                    match $uncompress(affine.as_mut_ptr(), compressed.as_ref().as_ptr()) {
                        BLST_ERROR::BLST_SUCCESS => {}
                        BLST_ERROR::BLST_BAD_ENCODING => return Err(ECGroupError::InvalidEncoding),
                        BLST_ERROR::BLST_POINT_NOT_ON_CURVE => {
                            return Err(ECGroupError::NotOnCurve)
                        }
                        other => unreachable!("{other:?}"),
                    }
                    if !$affine_in_group(affine.as_ptr()) {
                        return Err(ECGroupError::NotInGroup);
                    }

                    $from_affine(out.as_mut_ptr(), affine.as_ptr());
                    Ok(Self {
                        element: out.assume_init(),
                    })
                }
            }
        }
    };
}

impl_group!(
    P1,
    blst_p1,
    blst_p1_affine,
    blst_p1_from_affine,
    blst_p1_to_affine,
    p1_affines,
    BLS12_381_G1,
    BLS12_381_NEG_G1,
    blst_p1_add,
    blst_p1_cneg,
    blst_p1_mult,
    blst_p1_affine_in_g1,
    blst_p1_compress,
    blst_p1_uncompress,
    48
);

impl_group!(
    P2,
    blst_p2,
    blst_p2_affine,
    blst_p2_from_affine,
    blst_p2_to_affine,
    p2_affines,
    BLS12_381_G2,
    BLS12_381_NEG_G2,
    blst_p2_add,
    blst_p2_cneg,
    blst_p2_mult,
    blst_p2_affine_in_g2,
    blst_p2_compress,
    blst_p2_uncompress,
    96
);

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
