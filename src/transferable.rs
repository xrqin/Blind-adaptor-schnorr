use curv::elliptic::curves::{secp256_k1::Secp256k1Scalar as Scalar,secp256_k1::Secp256k1Point as Point, ECScalar, ECPoint};
use scuttlebutt::AbstractChannel;
use std::convert::TryInto;

pub trait Transferable 
where Self: Sized{
    fn write_channel<C: AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()>;
    fn read_channel<C: AbstractChannel>(chan: &mut C) -> anyhow::Result<Self>;
}

impl Transferable for Scalar {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let encoded: [u8;32] = self.serialize().try_into()?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;32];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded).map_err(|_| anyhow::anyhow!("failed to deserialize g1 point"))
        
    }
}

impl Transferable for Point {
    fn write_channel<C: scuttlebutt::AbstractChannel>(&self, chan: &mut C) -> anyhow::Result<()> {
        let generic_array = self.serialize_compressed();
        let slice = &generic_array[..];
        let encoded: [u8; 48] = slice.try_into().map_err(|_| anyhow::anyhow!("Failed to convert to a fixed-size array"))?;
        chan.write_bytes(&encoded)?;
        Ok(())
    }

    fn read_channel<C: scuttlebutt::AbstractChannel>(chan: &mut C) -> anyhow::Result<Self> {
        let mut encoded = [0u8;48];
        chan.read_bytes(&mut encoded)?;
        Self::deserialize(&encoded).map_err(|_| anyhow::anyhow!("failed to deserialize g1 point"))
        
    }
}
