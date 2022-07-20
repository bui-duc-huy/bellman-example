use bellman::{
    gadgets::{
        boolean::{
            AllocatedBit, 
            Boolean
        },
        multipack,
        sha256::sha256
    },
    Circuit, ConstraintSystem, SynthesisError
};

use ff::PrimeField;

/// Input and output are in little-endian bit order.
fn impl_sha256<Scalar: PrimeField, CS: ConstraintSystem<Scalar>> (
    mut cs: CS,
    data: &[Boolean]
) -> Result<Vec<Boolean>, SynthesisError> {
    let input: Vec<_> = data.chunks(8).map(|c| c.iter().rev()).flatten().cloned().collect();

    let res = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;

    Ok(res.chunks(8).map(|c| c.iter().rev()).flatten().cloned().collect())
}

pub struct OurProblem {
    pub value: Option<[u8; 80]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for OurProblem {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let bit_values = if let Some(value) = self.value {
            value.into_iter().map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).flatten().map(|b| Some(b)).collect()
        } else {
            vec![None; 80 * 8]
        };

        let pre_bit = bit_values.into_iter().enumerate().map(|(i, b)| {
            AllocatedBit::alloc(cs.namespace(|| format!("Pre bit {}", i)), b)
        }).map(|b| b.map(Boolean::from))
        .collect::<Result<Vec<_>, _>>()?;

        let hash = impl_sha256(cs.namespace(|| "SHA-256(value)"), &pre_bit)?;

        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}
