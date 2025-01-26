use ascon_prng::AsconMac;
use digest::{FixedOutput, Mac};
use libtest_mimic::{run, Arguments, Trial};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TestData {
    count: usize,
    #[serde(with = "hex::serde")]
    key: [u8; 16],
    #[serde(with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(with = "hex::serde")]
    tag: [u8; 16],
}

fn main() {
    let args = Arguments::from_args();

    let tests: Vec<TestData> =
        serde_json::from_str(&std::fs::read_to_string("tests/ascon_mac.json").unwrap()).unwrap();

    let trials = tests.into_iter().map(trial).collect();

    run(&args, trials).exit();
}

fn trial(test: TestData) -> Trial {
    Trial::test(format!("ascon_mac_{}", test.count), move || {
        let tag: [u8; 16] = AsconMac::new(&test.key.into())
            .chain_update(&test.msg)
            .finalize_fixed()
            .into();

        assert_eq!(tag, test.tag);

        Ok(())
    })
}
