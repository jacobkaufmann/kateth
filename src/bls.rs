use std::{
    mem::MaybeUninit,
    ops::{Add, Div, Mul, Sub},
};

use blst::{
    blst_bendian_from_scalar, blst_fp, blst_fr, blst_fr_add, blst_fr_eucl_inverse,
    blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_mul, blst_fr_sub, blst_p1, blst_p1_add,
    blst_p1_affine, blst_p1_affine_in_g1, blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult,
    blst_p2, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_deserialize, blst_p2_from_affine,
    blst_scalar, blst_scalar_fr_check, blst_scalar_from_bendian, blst_scalar_from_fr,
    blst_scalar_from_uint64, blst_uint64_from_fr, BLST_ERROR,
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

impl<T: AsRef<Fr>> From<T> for Scalar {
    fn from(element: T) -> Self {
        let mut out = MaybeUninit::<blst_scalar>::uninit();
        unsafe {
            blst_scalar_from_fr(out.as_mut_ptr(), &element.as_ref().element);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

impl AsRef<Self> for Scalar {
    fn as_ref(&self) -> &Self {
        self
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

    pub fn from_scalar(scalar: impl AsRef<Scalar>) -> Option<Self> {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_scalar_fr_check(&scalar.as_ref().element).then(|| {
                blst_fr_from_scalar(out.as_mut_ptr(), &scalar.as_ref().element);
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
            Self::from_scalar(Scalar {
                element: scalar.assume_init(),
            })
        }
    }

    pub fn as_u64(&self) -> u64 {
        let mut out = [0, 0, 0, 0];
        unsafe {
            blst_uint64_from_fr(out.as_mut_ptr(), &self.element);
        }
        out[0]
    }

    pub fn pow(&self, power: impl AsRef<Self>) -> Self {
        let power = Scalar::from(power);
        let mut power_be_bytes = [0u8; 32];
        unsafe {
            blst_bendian_from_scalar(power_be_bytes.as_mut_ptr(), &power.element);
        }
        let mut power = alloy_primitives::U256::from_be_bytes(power_be_bytes);
        let one = alloy_primitives::U256::from(1u64);

        let mut out = *self;
        let mut tmp = Self::ONE;
        while power > one {
            // remaining power odd
            if power.bit(0) {
                tmp = out * tmp;
                power -= one;
            }

            out = out * out;
            power >>= 1;
        }

        out = out * tmp;
        out
    }
}

impl AsRef<Self> for Fr {
    fn as_ref(&self) -> &Self {
        self
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

impl Mul for Fr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        unsafe {
            blst_fr_mul(out.as_mut_ptr(), &self.element, &rhs.element);
            Self {
                element: out.assume_init(),
            }
        }
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

    pub fn from_be_bytes(bytes: impl AsRef<[u8; Self::BYTES]>) -> Result<Self, ECGroupError> {
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
}

impl AsRef<Self> for P1 {
    fn as_ref(&self) -> &Self {
        self
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

impl Mul<Scalar> for P1 {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        let mut out = MaybeUninit::<blst_p1>::uninit();
        unsafe {
            blst_p1_mult(out.as_mut_ptr(), &self.element, rhs.element.b.as_ptr(), 255);
            Self {
                element: out.assume_init(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct P2 {
    element: blst_p2,
}

impl P2 {
    pub const BITS: usize = 768;
    pub const BYTES: usize = Self::BITS / 8;

    pub fn from_be_bytes(bytes: impl AsRef<[u8; Self::BYTES]>) -> Result<Self, ECGroupError> {
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
}

impl AsRef<Self> for P2 {
    fn as_ref(&self) -> &Self {
        self
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
