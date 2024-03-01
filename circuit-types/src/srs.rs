//! Defines the parsing logic for the SRS of the system
//!
//! The SRS was pulled from:
//!     https://github.com/iden3/snarkjs?tab=readme-ov-file#7-prepare-phase-2
//! For a max-constraints of 2^17, then split into ~50MB files by running:
//!     `split -d -b 50M <SRS FILE> srs`
//! So that the files can be hosted in this repo without Git LFS
//!
//! The SRS can be verified with `snarkjs powersoftau verify srs.ptau`
//! Which runs the algorithm in https://eprint.iacr.org/2017/1050.pdf
//!
//! The parsing logic here is heavily derived from:
//!     https://docs.rs/crate/ppot-rs/0.1.1
//! With special care taken to suit our use case:
//!     - Read from an included byte artifact directly
//!     - Parse directly into `UnivariateUniversalParams`
//!     - Simplified interface for lazy initialization
use std::io::{Cursor, Read, Result as IoResult, Seek, SeekFrom};

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::BigInt;
use ark_serialize::CanonicalDeserialize;
use byteorder::{LittleEndian, ReadBytesExt};
use constants::SystemCurve;
use jf_primitives::pcs::prelude::UnivariateUniversalParams;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use renegade_crypto::fields::get_base_field_modulus;

lazy_static! {
    /// The system SRS included from the `.ptau` file
    pub static ref SYSTEM_SRS: UnivariateUniversalParams<SystemCurve> = {
        let bytes_0 = include_bytes!("../../srs/srs00");
        let bytes_1 = include_bytes!("../../srs/srs01");
        let bytes_2 = include_bytes!("../../srs/srs02");
        let mut bytes = vec![];
        bytes.extend_from_slice(bytes_0);
        bytes.extend_from_slice(bytes_1);
        bytes.extend_from_slice(bytes_2);
        parse_ptau_file(&bytes).unwrap()
    };
}

/// The maximum power of two that the SRS supports
const MAX_SRS_POWER: usize = 17;
/// The maximum degree that the SRS supports
pub const MAX_SRS_DEGREE: usize = (1 << MAX_SRS_POWER) + 2;

/// The number of bytes in the magic string
const MAGIC_STRING_LEN: usize = 4;
/// The expected magic string
const MAGIC_STRING: &[u8; MAGIC_STRING_LEN] = b"ptau";
/// The expected version of the ptau file
const EXPECTED_VERSION: u32 = 1;
/// The expected number of sections in a ptau file
const EXPECTED_NUM_SECTIONS: u32 = 11;

// -----------
// | Parsing |
// -----------

/// Parse the bytes from the .ptau file into a set of params
pub fn parse_ptau_file(bytes: &[u8]) -> IoResult<UnivariateUniversalParams<Bn254>> {
    let mut cursor = Cursor::new(bytes);
    read_ptau_header(&mut cursor)?;
    read_ptau_section1(&mut cursor)?;
    let powers_of_g = read_ptau_section2(&mut cursor)?;
    let (h, beta_h) = read_ptau_section3(&mut cursor)?;

    Ok(UnivariateUniversalParams { powers_of_g, h, beta_h })
}

/// Read the header of a ptau file and validate its contents
fn read_ptau_header(cursor: &mut Cursor<&[u8]>) -> IoResult<()> {
    // Read the first 4 bytes as a magic string "ptau"
    let mut magic_string = [0u8; MAGIC_STRING_LEN];
    cursor.read_exact(&mut magic_string)?;
    assert_eq!(&magic_string, MAGIC_STRING);

    // Read the version
    let version = cursor.read_u32::<LittleEndian>()?;
    assert_eq!(
        version, EXPECTED_VERSION,
        "Invalid version, cannot parse ptau files of version != 1"
    );

    // Read the number of sections
    let num_sections = cursor.read_u32::<LittleEndian>()?;
    assert_eq!(num_sections, EXPECTED_NUM_SECTIONS, "Invalid number of sections");

    Ok(())
}

/// Read the first section of a ptau file, which contains the curve parameters
fn read_ptau_section1(cursor: &mut Cursor<&[u8]>) -> IoResult<()> {
    // Read the header of the section
    let (section_num, header_size) = read_section_header(cursor)?;
    assert_eq!(section_num, 1, "Invalid section number");

    let header_end = cursor.stream_position()? + header_size;

    // Read the number of bytes in the modulus
    let mod_bytes = cursor.read_u32::<LittleEndian>()?;
    let mut modulus = vec![0u8; mod_bytes as usize];
    cursor.read_exact(&mut modulus)?;

    let recovered_mod = BigUint::from_bytes_le(&modulus);
    assert_eq!(recovered_mod, get_base_field_modulus());

    // Read the power and the ceremony power
    let power = cursor.read_u32::<LittleEndian>()?;
    let _ceremony_power = cursor.read_u32::<LittleEndian>()?;
    assert!(power >= MAX_SRS_POWER as u32);

    // Seek to the next section
    cursor.seek(SeekFrom::Start(header_end))?;
    Ok(())
}

/// Read the second section of a ptau file, which contains the G1 points
///
/// These points are the powers of \tau from [0, MAX_SRS_DEGREE] multiplied by
/// the generator of the G1 group
fn read_ptau_section2(cursor: &mut Cursor<&[u8]>) -> IoResult<Vec<G1Affine>> {
    // Read the header of the section
    let (section_num, section_size) = read_section_header(cursor)?;
    assert_eq!(section_num, 2, "Invalid section number");

    let section_end = cursor.stream_position()? + section_size;

    // Read in the G1 points, which are the powers of \tau from [0, MAX_SRS_DEGREE]
    let mut powers_of_g = Vec::with_capacity(MAX_SRS_DEGREE + 1);
    for _ in 0..=MAX_SRS_DEGREE {
        let point = read_g1_point(cursor)?;
        powers_of_g.push(point);
    }

    // Seek to the next section
    cursor.seek(SeekFrom::Start(section_end))?;
    Ok(powers_of_g)
}

/// Read the third section of a ptau file, which contains the G2 points
///
/// These points are the generator of the G2 group and \tau * the generator of
/// the G2 group
fn read_ptau_section3(cursor: &mut Cursor<&[u8]>) -> IoResult<(G2Affine, G2Affine)> {
    // Read the header of the section
    let (section_num, _size) = read_section_header(cursor)?;
    assert_eq!(section_num, 3, "Invalid section number");

    // Read in the G2 points, these are the G2 generator H and \tau * H
    let h = read_g2_point(cursor)?;
    let beta_h = read_g2_point(cursor)?;

    Ok((h, beta_h))
}

// -----------
// | Helpers |
// -----------

/// Read a section number and size from a cursor
fn read_section_header(cursor: &mut Cursor<&[u8]>) -> IoResult<(u32, u64)> {
    let section_num = cursor.read_u32::<LittleEndian>()?;
    let section_size = cursor.read_u64::<LittleEndian>()?;

    Ok((section_num, section_size))
}

/// Read a Bn254 G1 affine point from a cursor
fn read_g1_point(cursor: &mut Cursor<&[u8]>) -> IoResult<G1Affine> {
    let x = read_base_field_element(cursor)?;
    let y = read_base_field_element(cursor)?;

    // Use `new_unchecked` here to avoid the subgroup check -- which is very slow
    // We check only whether the point is a valid curve member
    let res = G1Affine::new_unchecked(x, y);
    assert!(res.is_on_curve(), "point not on curve");

    Ok(res)
}

/// Read a Bn254 G2 affine point from a cursor
fn read_g2_point(cursor: &mut Cursor<&[u8]>) -> IoResult<G2Affine> {
    let x0 = read_base_field_element(cursor)?;
    let x1 = read_base_field_element(cursor)?;
    let y0 = read_base_field_element(cursor)?;
    let y1 = read_base_field_element(cursor)?;

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    let res = G2Affine::new_unchecked(x, y);
    assert!(res.is_on_curve(), "point not on curve");

    Ok(res)
}

/// Read a base field element from a cursor
fn read_base_field_element(cursor: &mut Cursor<&[u8]>) -> IoResult<Fq> {
    let biguint = BigInt::deserialize_uncompressed(cursor).map_err(|e| {
        invalid_data_error(&format!("Failed to deserialize base field element: {}", e))
    })?;

    // Points are serialized in their Montgomery form, use `new_unchecked` to avoid
    // the implicit conversion
    Ok(Fq::new_unchecked(biguint))
}

/// Create a new invalid data error with a message
fn invalid_data_error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

// TODO: Test the parsing logic
#[cfg(test)]
mod test {
    use ark_bn254::{Bn254, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use rand::{seq::IteratorRandom, thread_rng};

    use crate::srs::MAX_SRS_DEGREE;

    use super::SYSTEM_SRS;

    /// Checks that the ratio between two sets of points is the same with one
    /// set in G1 and one set in G2
    ///
    /// I.e. for (A, B) \in G_1^2, (C, D) \in G_2^2 check that there exists x
    /// such that B = A * x and D = C * x
    fn same_ratio(a: &G1Affine, b: &G1Affine, c: &G2Affine, d: &G2Affine) -> bool {
        Bn254::pairing(a, d) == Bn254::pairing(b, c)
    }

    /// Tests that the parsed SRS is the correct length
    #[test]
    fn test_srs_length() {
        let srs = SYSTEM_SRS.clone();
        assert_eq!(srs.powers_of_g.len(), MAX_SRS_DEGREE + 1);
    }

    /// Tests that the SRS is a valid set of powers of tau
    ///
    /// Effectively uses a simplified version of the verification method in:
    ///     https://eprint.iacr.org/2017/1050.pdf  
    ///
    /// We subsample the SRS here to keep the test runtime reasonable, since the
    /// invariant checked here should be held uniformly, this should be
    /// sufficient
    #[test]
    fn test_srs_powers() {
        const NUM_SAMPLES: usize = 100;
        let mut rng = thread_rng();
        let srs = SYSTEM_SRS.clone();

        // Check the ratio between the successive powers against the ratio between H and
        // \beta * H. These ratios should all be \beta, the secret exponent
        let h = &srs.h;
        let beta_h = &srs.beta_h;

        for window in srs.powers_of_g.windows(2 /* size */).choose_multiple(&mut rng, NUM_SAMPLES) {
            let (a, b) = (&window[0], &window[1]);
            assert!(same_ratio(a, b, h, beta_h));
        }
    }
}
