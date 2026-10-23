use ml_kem::kem::Decapsulate;
use ml_kem::{Encoded, EncodedSizeUser, EncapsulateDeterministic, KemCore, MlKem768};
use serde::Deserialize;

#[derive(Deserialize)]
struct File { #[serde(rename = "testGroups")] groups: Vec<Group> }
#[derive(Deserialize)]
struct Group {
    #[serde(rename = "parameterSet")] ps: String,
    function: Option<String>,
    tests: Vec<T>,
}
#[derive(Deserialize)]
struct T {
    #[serde(rename = "tcId")] id: u32,
    d: Option<String>, z: Option<String>, m: Option<String>,
    ek: Option<String>, dk: Option<String>, c: Option<String>, k: Option<String>,
}
fn h(s: &Option<String>) -> Vec<u8> { hex::decode(s.as_ref().unwrap()).unwrap() }
fn load(p: &str) -> File { serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() }

#[test]
fn kat_keygen_768() {
    let mut n = 0;
    for g in load("tests/vectors/keygen.json").groups.iter().filter(|g| g.ps == "ML-KEM-768") {
        for t in &g.tests {
            let (dk, ek) = MlKem768::generate_deterministic(
                h(&t.d).as_slice().try_into().unwrap(),
                h(&t.z).as_slice().try_into().unwrap(),
            );
            assert_eq!(ek.as_bytes().as_slice(), h(&t.ek).as_slice(), "ek tc {}", t.id);
            assert_eq!(dk.as_bytes().as_slice(), h(&t.dk).as_slice(), "dk tc {}", t.id);
            n += 1;
        }
    }
    assert!(n > 0);
    println!("keygen KATs passed: {n}");
}

#[test]
fn kat_encapsulation_768() {
    let mut n = 0;
    for g in load("tests/vectors/encapdecap.json").groups.iter()
        .filter(|g| g.ps == "ML-KEM-768" && g.function.as_deref() == Some("encapsulation"))
    {
        for t in &g.tests {
            let ek_bytes: Encoded<<MlKem768 as KemCore>::EncapsulationKey> =
                h(&t.ek).as_slice().try_into().unwrap();
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
            let (c, k) = ek.encapsulate_deterministic(h(&t.m).as_slice().try_into().unwrap()).unwrap();
            assert_eq!(c.as_slice(), h(&t.c).as_slice(), "c tc {}", t.id);
            assert_eq!(k.as_slice(), h(&t.k).as_slice(), "k tc {}", t.id);
            n += 1;
        }
    }
    assert!(n > 0);
    println!("encapsulation KATs passed: {n}");
}

#[test]
fn kat_decapsulation_768() {
    let mut n = 0;
    for g in load("tests/vectors/encapdecap.json").groups.iter()
        .filter(|g| g.ps == "ML-KEM-768" && g.function.as_deref() == Some("decapsulation"))
    {
        for t in &g.tests {
            let dk_bytes: Encoded<<MlKem768 as KemCore>::DecapsulationKey> =
                h(&t.dk).as_slice().try_into().unwrap();
            let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
            let k = dk.decapsulate(h(&t.c).as_slice().try_into().unwrap()).unwrap();
            assert_eq!(k.as_slice(), h(&t.k).as_slice(), "k tc {}", t.id);
            n += 1;
        }
    }
    assert!(n > 0);
    println!("decapsulation KATs passed: {n}");
}
