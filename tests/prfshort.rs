use ascon_prng::ascon_prf_short;
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
        serde_json::from_str(&std::fs::read_to_string("tests/ascon_prfshort.json").unwrap())
            .unwrap();

    let trials = tests.into_iter().map(trial).collect();

    run(&args, trials).exit();
}

fn trial(test: TestData) -> Trial {
    Trial::test(format!("ascon_prfshort_{}", test.count), move || {
        let mut output = [0; 16];
        ascon_prf_short(test.key, &test.msg, &mut output);
        assert_eq!(output, test.tag);

        Ok(())
    })
}
