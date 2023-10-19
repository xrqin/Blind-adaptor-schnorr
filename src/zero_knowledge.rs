use curv::elliptic::curves::{ECScalar,ECPoint}; // This brings the trait into scope
use curv::elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar, self};
use curv::{BigInt, arithmetic::Converter};
use sha2::{Sha256, Digest};

pub struct CommitmentEqualityProof {
    mask_com1: Point,
    mask_com2: Point,
    result_m: Scalar,
    result_r1: Scalar,
    result_r2: Scalar
}

impl CommitmentEqualityProof {
    pub fn prove(
        m: &Scalar,
        r1: &Scalar,
        r2: &Scalar
    ) -> Self {
        let mask_m = Scalar::random();
        let mask_r1 = Scalar::random();
        let mask_r2 = Scalar::random();
        let g = Point::generator();  // get the generator point
        let h = Point::base_point2(); // get the second base point if it exists; this is curve-dependent
        let mask_com1 = g.scalar_mul(&mask_m).add_point(&h.scalar_mul(&mask_r1)); // This assumes `add_point` is a valid method for adding two points.
        let mask_com2 = g.scalar_mul(&mask_m).add_point(&h.scalar_mul(&mask_r2)); // This assumes `add_point` is a valid method for adding two points.
        let challenge = Scalar::from_bigint(&BigInt::from_bytes(
            Sha256::digest(
                &[mask_com1.serialize_compressed(), mask_com2.serialize_compressed()].concat()
            )
            .as_ref(), // Convert GenericArray to &[u8] using as_ref()
        ));
        
        let result_m = mask_m.add(&challenge.mul(&m));
        let result_r1 = mask_r1.add(&challenge.mul(&r1));
        let result_r2 = mask_r2.add(&challenge.mul(&r2));
        Self { mask_com1, mask_com2, result_m, result_r1, result_r2 }
    }

    pub fn verify(&self, com1: &Point, com2: &Point) -> anyhow::Result<()>{
        let challenge = Scalar::from_bigint(&BigInt::from_bytes(
            Sha256::digest(
                &[com1.serialize_compressed(), com2.serialize_compressed()].concat()
            )
            .as_ref(), // Convert GenericArray to &[u8] using as_ref()
        ));
        if Point::generator_mul(&self.result_m).add_point(&Point::base_point2().scalar_mul(&self.result_r1)) != com1.scalar_mul(&challenge).add_point(&&self.mask_com1){
            return Err(anyhow::anyhow!("mask for commitment 1 not correct"))
        }
        if Point::generator_mul(&self.result_m).add_point(&Point::base_point2().scalar_mul(&self.result_r2)) != com2.scalar_mul(&challenge).add_point(&&self.mask_com2){
            return Err(anyhow::anyhow!("mask for commitment 2 not correct"))
        }
        Ok(())
    }

    pub fn serialize(&self) -> [u8;192]{
        let mut result = [0u8;192];
        result[  0.. 48].copy_from_slice(&self.mask_com1.serialize_compressed().as_ref());
        result[ 48.. 96].copy_from_slice(&self.mask_com2.serialize_compressed().as_ref());
        result[ 96..128].copy_from_slice(&self.result_m.serialize().as_ref());
        result[128..160].copy_from_slice(&self.result_r1.serialize().as_ref());
        result[160..192].copy_from_slice(&self.result_r2.serialize().as_ref());
        result
    }

    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self>{
        Ok(Self{
            mask_com1: Point::deserialize(
                &data[  0.. 48]).map_err(|_|anyhow::anyhow!("failed to parse mask_com1"))?,
            mask_com2: Point::deserialize(
                &data[ 48.. 96]).map_err(|_|anyhow::anyhow!("failed to parse mask_com2"))?,
            result_m:  Scalar::deserialize(
                &data[ 96..128]).map_err(|_|anyhow::anyhow!("failed to parse result_m"))?,
            result_r1: Scalar::deserialize(
                &data[128..160]).map_err(|_|anyhow::anyhow!("failed to parse result_r1"))?,
            result_r2: Scalar::deserialize(
                &data[160..192]).map_err(|_|anyhow::anyhow!("failed to parse result_r2"))?
        })
    }
}


#[cfg(test)]
mod tests{
    use curv::elliptic::curves::{ECScalar,ECPoint}; // This brings the trait into scope
    use curv::elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar, self};
    use curv::{BigInt, arithmetic::Converter};
    use sha2::{Sha256, Digest};

    use super::CommitmentEqualityProof;

    #[test]
    fn test_commitment_equality() {
        let m = Scalar::random();
        let r1 = Scalar::random();
        let r2 = Scalar::random();
        let com1 = Point::generator_mul(&m).add_point(&Point::base_point2().scalar_mul(&r1));
        let com2 = Point::generator_mul(&m).add_point(&Point::base_point2().scalar_mul(&r2));
        let proof = CommitmentEqualityProof::prove(&m, &r1, &r2);
        CommitmentEqualityProof::deserialize(&proof.serialize()).unwrap().verify(&com1, &com2).unwrap();
    }
}