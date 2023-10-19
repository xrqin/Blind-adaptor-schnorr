use std::ops::{Mul, Add};
use curv::{elliptic::curves::{secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar, self},Curve, ECPoint, ECScalar}, arithmetic::Samplable, cryptographic_primitives::hashing::DigestExt};
//use kzen_paillier::{*, serialize::bigint};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rust_elgamal::{EncryptionKey, DecryptionKey, Scalar as Elg_Scalar, GENERATOR_TABLE};
use sha2::{Sha256,Digest};
use curv::arithmetic::*;
use fancy_garbling::{circuit::Circuit, twopac::semihonest::{Garbler, Evaluator}, FancyInput, Wire, encode_boolean, decode_boolean};
use ocelot::ot::{NaorPinkasReceiver, NaorPinkasSender};
use scuttlebutt::{AbstractChannel, AesRng};
use num_bigint::{BigInt as NumBigInt, Sign};
use anyhow::Result;
use hex;

use blind_adaptor_schnorr::{zero_knowledge::CommitmentEqualityProof, transferable::Transferable};



pub struct User{}
pub struct Signer{}

//#[derive(serde::Serialize, serde_derive::Deserialize)]
pub struct encrypted_message{
    pub message: BigInt,
    pub alpha: Scalar,
    pub beta: Scalar
}

pub struct User_state{
    pub alpha: Scalar,
    pub beta: Scalar,
    pub rho: Scalar
}

pub struct User_Message{
    pub r_prime: Scalar,
    pub h_prime: Scalar
}

pub struct User_Output_1{
    pub ciphertext: Scalar,
    pub user_state: User_state
}

pub struct User_Output_2{
    pub ciphertext_point: Point,
    pub proof: BigInt
}

fn hash_to_scalar<C: Curve>(value: &BigInt) -> Scalar {
    let hash = Sha256::digest(&value.to_bytes());
    let bigint_val = BigInt::from_bytes(hash.as_slice());
    Scalar::from_bigint(&bigint_val)
}

pub fn encode_message(
    R: &Point,
    X: &Point,
    m: &BigInt
) -> Result<[u8;96]>{
    let mut result = [0u8; 96];

    // Use the correct method to serialize the points to bytes
    let r_bytes = R.serialize_compressed(); // or R.serialize(), R.serialize_uncompressed(), depending on what's available and needed
    let x_bytes = X.serialize_compressed(); // same as above

    // Ensure these serialized values are in the correct format (e.g., Vec<u8>) for the copy_from_slice method
    result[..32].copy_from_slice(&r_bytes[..]);
    result[32..64].copy_from_slice(&x_bytes[..]);

    // Assuming m.to_bytes() is correct and m is of a type that has a to_bytes method
    result[64..96].copy_from_slice(&m.to_bytes());

    Ok(result)
}

fn encode_index_from_mpc_native(start: usize) -> [usize;64] {
    const OFFSET: [usize; 64] = [
        07, 06, 05, 04, 03, 02, 01, 00,
        15, 14, 13, 12, 11, 10, 09, 08,
        23, 22, 21, 20, 19, 18, 17, 16,
        31, 30, 29, 28, 27, 26, 25, 24,
        39, 38, 37, 36, 35, 34, 33, 32,
        47, 46, 45, 44, 43, 42, 41, 40,
        55, 54, 53, 52, 51, 50, 49, 48,
        63, 62, 61, 60, 59, 58, 57, 56,
    ];
    let mut result = [start; 64];
    result.iter_mut().enumerate().for_each(|(i, a)| {
        *a += OFFSET[i];
    });
    result
}

fn write_amount_commitment<C: AbstractChannel>(
    channel: &mut C,
    start: usize,
    zs: &[Scalar],
    scalar2: &Scalar
) -> anyhow::Result<Scalar> {
    let message = encode_index_from_mpc_native(start).into_iter()
        .map(|index| &zs[index])
        .fold(Scalar::zero(), |sum, each| 
            sum.mul(&scalar2).add(each)
    );
    let randomness = Scalar::random();
    Point::generator().scalar_mul(&message).add_point(
        &Point::base_point2().scalar_mul(&randomness)
    ).write_channel(channel)?;
    Ok(randomness)
}

pub fn zkgc_evaluator<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Evaluator<C, AesRng, NaorPinkasReceiver>,
    R: &Point,
    X: &Point,
    m: &BigInt,
    commitment_m_rand: &Scalar,
) -> anyhow::Result<()>{
    let ev_inputs_bytes = encode_message(
        &R,
        &X,
        m,
    ).unwrap();
    // convert the byte array to a hexadecimal string
    let ev_inputs_hex = hex::encode(&ev_inputs_bytes); 
    let ev_inputs_binary = encode_boolean(&ev_inputs_hex, true).unwrap();    let ev_inputs = f.encode_many(
        &ev_inputs_binary,
        &[2u16;768]
    )?;//commit oblivious transfer
    f.get_channel().flush()?;
    let label_wire = circ.eval_label(f, &vec![], &ev_inputs)?;//evaluation result, \hat{Z}
    f.get_channel().flush()?;

    let encode_message = [
        m.to_bytes(),
    ].concat();

    let encode_message_hex = hex::encode(&encode_message); // This converts the Vec<u8> to a hexadecimal string

    let zs: Vec<Scalar> = encode_boolean(&encode_message_hex, true)
    .map_err(|_| anyhow::anyhow!("failed to encode boolean"))?
        .into_iter()
        .zip(&ev_inputs)
        .map(|(bit, wire)| {
            let c0 = Scalar::read_channel(f.get_channel())?;
            let c1 = Scalar::read_channel(f.get_channel())?;
            let wire_block = match wire {
                Wire::Mod2 { val } => Ok(val),
                _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
            }?;
            // Inside your function where you have access to `wire_block`
        let wire_block_ptr = wire_block.as_ptr(); // Get pointer to the data
        let wire_block_slice = unsafe { std::slice::from_raw_parts(wire_block_ptr, 16) }; // Create a slice from the pointer; 16 is the size of the block
            match bit{
                0 => Ok(c0.sub(&Scalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(wire_block_slice).as_slice())))),
                1 => Ok(c1.sub(&Scalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(wire_block_slice).as_slice())))),
                _ => Err(anyhow::anyhow!("failed to encode boolean"))
            }
        }
    ).collect::<anyhow::Result::<_>>()?; 
    let scalar2 = Scalar::from_bigint(&BigInt::from(2));
    let com_temp_rand = write_amount_commitment(f.get_channel(), 000, &zs, &scalar2)?;
    f.get_channel().flush()?;
    let delta_inv = Scalar::read_channel(f.get_channel())?.invert().unwrap();
    let com_trans_temp_rand = com_temp_rand.mul(&delta_inv);
    let com_eq_trans = CommitmentEqualityProof::prove(
        &Scalar::from_bigint(&m),
        &com_trans_temp_rand,
        &commitment_m_rand,
    );
    f.get_channel().write_bytes(&com_eq_trans.serialize())?;
    Ok(())
}

pub fn zkgc_garbler<C: AbstractChannel>(
    circ: &Circuit,
    f: &mut Garbler<C, AesRng, NaorPinkasSender>,
) -> anyhow::Result<[u8;32]>{
    let ev_inputs = f.receive_many(&[2u16;256])?;
    f.get_channel().flush()?;
    let label_wire = circ.eval_label(f, &vec![], &ev_inputs)?;
    f.get_channel().flush()?;
    let mut zs = Vec::with_capacity(128);
    let delta = Scalar::random();
    for w0 in &ev_inputs[0..128]{
        let z0 = Scalar::random();
        let z1 = z0.add(&delta);

        zs.push(z0.clone());
        let w1 = w0.plus(&f.delta(2));
        let w0_block = match w0{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 0 is not modulo 2"))
        }?;
        let w1_block = match &w1{
            Wire::Mod2 { val } => Ok(val),
            _ => Err(anyhow::anyhow!("wire 1 is not modulo 2"))
        }?;
        let w0_block_ptr = w0_block.as_ptr(); // Get pointer to the data
        let w1_block_ptr = w1_block.as_ptr(); // Get pointer to the data
        let w0_block_slice = unsafe { std::slice::from_raw_parts(w0_block_ptr, 16) }; // Create a slice from the pointer; 16 is the size of the block
        let w1_block_slice = unsafe { std::slice::from_raw_parts(w1_block_ptr, 16) }; // Create a slice from the pointer; 16 is the size of the block
        let c0 = z0.add(&Scalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w0_block_slice))));
        let c1 = z1.add(&Scalar::from_bigint(&BigInt::from_bytes(&Sha256::digest(&w1_block_slice))));
        c0.write_channel(f.get_channel())?;
        c1.write_channel(f.get_channel())?;
        // f.get_channel().write_scalar(&c0)?;
        // f.get_channel().write_scalar(&c1)?;
        // f.get_channel().flush()?;
    }
    f.get_channel().flush()?;
    let scalar2 = Scalar::from_bigint(&BigInt::from(2));
}


pub fn dhies_encrypt<C: Curve>(public_key: &Point, message: &BigInt) -> (Point, BigInt) {
    // 1. Choose a random value rho from F_q
    let rho = Scalar::random();

    // 2. Compute the shared secret rho * K
    let shared_secret_point = public_key.scalar_mul(&rho);
    let shared_secret_point_bytes = shared_secret_point.serialize_compressed(); // Serialize the point

    // 3. Hash the shared secret to derive a symmetric key
    let mut hasher = Sha256::new();
    hasher.update(&shared_secret_point_bytes);
    let hash = hasher.finalize();
    // Convert the hash to a hexadecimal string
    let hash_hex = hex::encode(&hash);

    // Convert the hexadecimal string to a curv::BigInt
    let hash_bigint = curv::BigInt::from_hex(&hash_hex).unwrap();



    // 4. Encrypt the message using this symmetric key (using an additive one-time pad over F_p)
    let encrypted_message = message + &hash_bigint;

    // 5. The ciphertext consists of the encrypted message and rho * G
    let rho_g = Point::generator().scalar_mul(&rho);

    (rho_g, encrypted_message)
}


impl User {
    pub fn sent_1<C: Curve>(K: &Point,  m: &BigInt)->User_Output_1{
        let alpha = Scalar::random();
        let beta = Scalar::random();
        let rho = Scalar::random();
        // 1. Hash the message
        //let m_scalar = hash_to_scalar(m);

        // Map the scalars to points on the curve
        //let m_point = m_scalar * &Point::generator().to_point();
        //let alpha_point = alpha * &Point::generator().to_point();
        //let beta_point = beta * &Point::generator().to_point();
        //let m_combined = m_point + alpha_point + beta_point;

        // Convert the combined point to bytes
        //let m_encoded = m_combined.to_bytes(true);
        //let m_bytes = m_encoded.as_ref();


        // Convert the bytes to a hexadecimal string
        //let m_hex = hex::encode(m_bytes);

        // Convert the hexadecimal string to a curv::BigInt
        //let m_bigint = curv::BigInt::from_hex(&m_hex).unwrap();

        //let (ciphertext_point, encrypted_message) = dhies_encrypt(K, &m_bigint);
        let m = Scalar::from_bigint(&m);
        let ciphertext = m.add(&rho);
        let user_state = User_state{
            alpha: alpha,
            beta: beta,
            rho: rho
        };
        User_Output_1 {
            ciphertext,
            user_state
        }
        }

    pub fn sent_2<C: Curve>(R: &Point, X: &Point, alpha: &Scalar, beta: &Scalar,  m: &BigInt)->User_Output_2
    where
    C: Curve + ECScalar, // adding the ECScalar trait bound here
    {   
        let alpha_G = Point::generator().scalar_mul(&alpha);
        let beta_X = X.scalar_mul(&beta);
        let R_prime = R.add_point(&alpha_G).add_point(&beta_X);
        
        // Convert R_prime, X, and m to byte representations
        let r_prime_bytes = R_prime.serialize_compressed();
        let x_bytes = X.serialize_compressed();
        let m_bytes = m.to_bytes(); // Replace 'to_bytes' with whatever method curv provides, if it exists.


        let mut data_to_hash = Vec::new();
        data_to_hash.extend_from_slice(&r_prime_bytes); // Use `&` if `to_bytes` returns a Vec<u8>
        data_to_hash.extend_from_slice(&x_bytes);
        data_to_hash.extend_from_slice(&m_bytes);


        // Hash the concatenated bytes
        let hash_result = Sha256::digest(&data_to_hash); 

        // Convert the hash result to a BigInt (assuming the hash is in big-endian format)
        // Convert the hash result to a hexadecimal string
        let hash_hex = hex::encode(hash_result);

        // Convert the hexadecimal string to a BigInt
        let hash_bigint = BigInt::from_hex(&hash_hex).unwrap(); // Make sure to handle this unwrap properly in real code

        // Get the order of the group (you might need to adjust this part depending on the library you're using)
        let p = C::group_order(); // This is a placeholder. Replace with actual order of the group.

        // Reduce the hash modulo p to get a value in Zp
        let hash_mod_p = hash_bigint.modulus(p);

        // Convert beta to BigInt (if it's not already)
        let beta_bigint = beta.to_bigint(); // This method might be different based on your library

        // Add beta to the hash and reduce modulo p again
        let c = (hash_mod_p + beta_bigint).modulus(p);

        
       
    }

    pub fn verify<C: Curve>(s_prime: &Scalar, k_b: &Scalar, k_c: &Scalar, X: &Point, R: &Point, r: &BigInt, h: &BigInt)->Scalar{
        let s_prime_R = s_prime.mul(R);
        let r_X = Scalar::from_bigint(&r).mul(X);
        let h_G = Scalar::from_bigint(&h).mul(R);
        if s_prime_R != r_X.add(h_G){
            Scalar::zero()
        }
        else{
            let s_prime_k_c = Scalar::mul(s_prime.clone(), k_c.clone());
            let k_b_inv = k_b.invert().unwrap();
            let s = Scalar::mul(s_prime_k_c,k_b_inv);
            s
        }
    }
}

impl Signer {
    pub fn response<C: Curve>(x: &Scalar, k_a: &Scalar, z: &Scalar, r_prime: &Scalar, h_prime: &Scalar)->Scalar{
        let k_a_inv = k_a.invert().unwrap();
        let s_prime = Scalar::mul(k_a_inv, Scalar::mul(r_prime.clone(), x)+h_prime-z);
        s_prime
    }
}

