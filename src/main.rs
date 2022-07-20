use bellman::{
    gadgets::
        multipack::{
            compute_multipacking,
            bytes_to_bits_le
        },
    groth16::{
        generate_random_parameters,
        create_random_proof,
        prepare_verifying_key
    }
};
use rand::rngs::OsRng;
use bls12_381::Bls12;
use sha2::{Digest, Sha256};

mod problem;

fn main() {
    let params = {
        let c = problem::OurProblem { value: None };

        generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    let hidden_value = [40; 80];
    let hash_bit = bytes_to_bits_le(&Sha256::digest(&hidden_value));
    let _inputs = compute_multipacking(&hash_bit);

    let c = problem::OurProblem {
        value: Some(hidden_value),
    };

    let proof = create_random_proof(c, &params, &mut OsRng);

}
