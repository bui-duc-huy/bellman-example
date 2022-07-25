use bellman::{
    gadgets::
        multipack::{
            compute_multipacking,
            bytes_to_bits_le
        },
    groth16::{
        generate_random_parameters,
        create_random_proof,
        prepare_verifying_key,
        verify_proof
    }
};
use rand::rngs::OsRng;
use bls12_381::{Bls12, Scalar};
use sha2::{Digest, Sha256};

mod problem;

fn main() {
    println!("Learn zk-SNARKs with Terry");
    let params = {
        let c = problem::OurProblem { value: None };

        generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };

    println!("Prepare key...");
    let pvk = prepare_verifying_key(&params.vk);

    println!("Prepare input...");
    let hidden_value = [40; 80];
    let hash_bit = bytes_to_bits_le(&Sha256::digest(&hidden_value));
    let x = compute_multipacking::<Scalar>(&hash_bit);

    let c = problem::OurProblem {
        value: Some(hidden_value),
    };

    println!("Create proof...");
    let proof = create_random_proof(c, &params, &mut OsRng).unwrap();

    println!("Verify proof...");
    let result = verify_proof(&pvk, &proof, &x);
    
    println!("Result: {}", result.is_ok());
}
