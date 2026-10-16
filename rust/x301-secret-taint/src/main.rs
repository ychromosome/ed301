use ed301_valgrind_client::{get_vbits, make_defined, mark_undefined, running_on_valgrind};
use x301_core::{SecretKey, X301Error, public_from_secret, shared_secret};

fn bytes(name: &str) -> Result<Vec<u8>, String> {
    let value = std::env::var(name).map_err(|_| format!("missing {name}"))?;
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err("invalid test hex".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "invalid test hex".to_owned())
        })
        .collect()
}

fn vbits(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut bits = vec![0_u8; input.len()];
    let result = get_vbits(input, &mut bits);
    make_defined(&mut bits);
    if result != 1 {
        return Err("GET_VBITS failed".into());
    }
    Ok(bits)
}

fn name(error: X301Error) -> &'static str {
    match error {
        X301Error::InvalidSecretLength => "secret-length",
        X301Error::WeakSecret => "weak-secret",
        X301Error::InvalidPublicLength => "public-length",
        X301Error::NonCanonicalPublic => "noncanonical-public",
        X301Error::AllZeroSharedSecret => "all-zero",
    }
}

fn main() -> Result<(), String> {
    if running_on_valgrind() == 0 {
        return Err("run under Valgrind".into());
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || !["defined", "tainted"].contains(&args[1].as_str()) {
        return Err("usage: public|shared|import defined|tainted".into());
    }
    let tainted = args[1] == "tainted";
    let mut secret = bytes("X301_CT_SECRET")?;
    let peer = bytes("X301_CT_PEER")?;
    let expected = bytes("X301_CT_EXPECTED")?;
    let expected_error = std::env::var("X301_CT_ERROR").map_err(|_| "missing error expectation")?;
    if tainted {
        mark_undefined(&mut secret[..]);
    }
    if !secret.is_empty()
        && vbits(&secret)?
            .iter()
            .any(|x| *x != if tainted { 0xff } else { 0 })
    {
        return Err("input taint mode was not actually set".into());
    }
    let result: Result<Vec<u8>, X301Error> = match args[0].as_str() {
        "public" => public_from_secret(&secret).map(|mut public| {
            assert!(
                vbits(&public).unwrap().iter().all(|x| *x == 0),
                "public output not declassified"
            );
            make_defined(&mut public);
            public.to_vec()
        }),
        "shared" => shared_secret(&secret, &peer).map(|shared| {
            let bits = vbits(shared.as_bytes()).unwrap();
            assert_eq!(
                bits.iter().any(|x| *x != 0),
                tainted,
                "shared output lost its secret taint"
            );
            let mut output = shared.as_bytes().to_vec();
            make_defined(&mut output[..]);
            output
        }),
        "import" => SecretKey::from_bytes(&secret).map(|key| {
            assert_eq!(
                vbits(key.as_bytes()).unwrap().iter().any(|x| *x != 0),
                tainted
            );
            let mut output = key.as_bytes().to_vec();
            make_defined(&mut output[..]);
            output
        }),
        _ => return Err("unknown operation".into()),
    };
    make_defined(&mut secret[..]);
    match result {
        Ok(output) => {
            if !expected_error.is_empty() || output != expected {
                return Err("positive KAT mismatch".into());
            }
        }
        Err(error) => {
            if name(error) != expected_error || !expected.is_empty() {
                return Err("error KAT mismatch".into());
            }
        }
    }
    println!("PASS: {} {} input_vbits_checked=1", args[0], args[1]);
    Ok(())
}
