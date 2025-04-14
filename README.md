# Circom + gnark Bridge (BN254 Groth16)

> **Disclaimer**  
> This is a prototype and **not intended for production**.  
> The code has **not been audited**.  
> Suggestions and contributions are welcome.

---

## Motivation

- Many SNARK proof systems use a similar frontend representation.
- Numerous systems target R1CS arithmetization over the BN254 scalar field.
- Ideally, you should be able to write BN254-based R1CS circuits in one library and prove them with a different library.
- This separation enables benchmarking the efficiency of different backend provers using the exact same R1CS.
- Keep in mind that the same arithmetic circuit can be arithmetized into R1CS in multiple ways. Some libraries may design their frontends specifically so that the backend prover can exploit particular structures in the resulting R1CS instances.

**Note:** This library currently supports only **Groth16 over BN254**.

---

## Solution Overview

### Setup

- Define your R1CS circuit in Circom and compile it into a `.r1cs` binary.
- Use this tool to:
  - Convert the `.r1cs` file to a gnark-compatible format.
  - Run `groth16.Setup()` to generate the prover and verifier keys.

### Compute and Prove

- Generate your witness using Circom/snarkjs to produce `witness.wtns`.
- Use this tool to:
  - Convert the witness into a format gnark understands.
  - Generate a proof using gnark.

### Verify

- Use this tool to verify the proof with gnark’s verifier.

---

## Example Commands

These should be run from specific working directories.

### Directory: `GnarkProveCircomCircuit/circom/simple_circom_circuit`

```bash
alias circom_simple="circom --r1cs --wasm --sym simple.circom"
alias circom_simple_witgen="node simple_js/generate_witness.js simple_js/simple.wasm input.json witness.wtns"
```

### Directory: `GnarkProveCircomCircuit/`

```bash
alias do_define="go run main.go parse_circom_helper.go dirty_builder.go dirty_builder_wrappers.go define_circuit circom/simple_circom_circuit/simple.r1cs gnarkCirc2.txt"
alias do_setup="go run main.go parse_circom_helper.go dirty_builder.go dirty_builder_wrappers.go setup_circuit gnarkCirc2.txt provKey2.txt verKey2.txt"
alias do_witness="go run main.go parse_circom_helper.go dirty_builder.go dirty_builder_wrappers.go import_witness circom/simple_circom_circuit/witness.wtns gnarkCirc2.txt gnarkWit2.txt pubInps2.txt"
alias do_prove="go run main.go parse_circom_helper.go dirty_builder.go dirty_builder_wrappers.go prove gnarkCirc2.txt provKey2.txt gnarkWit2.txt proof2.txt"
alias do_verify="go run main.go parse_circom_helper.go dirty_builder.go dirty_builder_wrappers.go verify verKey2.txt proof2.txt pubInps2.txt"
```

### Example `input.json`

Place this file in: `GnarkProveCircomCircuit/circom/simple_circom_circuit`

```json
{
  "x": "3",
  "y": "11"
}
```

---

## Running an Example

### Setup

```bash
cd GnarkProveCircomCircuit/circom/simple_circom_circuit
circom_simple

cd ../../
do_define
do_setup
```

### Compute and Prove

```bash
cd circom/simple_circom_circuit
# Make sure input.json is present
circom_simple_witgen

cd ../../
do_witness
do_prove
```

### Verify

```bash
do_verify
```

## Notes

Thanks to [Kobi Gurkan](https://github.com/kobigurk) for pointing out prior work in this area. For related efforts, see:

- [zkinterface by QED-it](https://github.com/QED-it/zkinterface)
- [circom-compat by arkworks-rs](https://github.com/arkworks-rs/circom-compat)

The gnark team has mentioned plans to support this functionality natively—so keep an eye out for future updates. 
In the meantime, feel free to use this tool however you’d like.

**Update:** [Vocdoni](https://github.com/vocdoni) has a project called [circom2gnark](https://github.com/vocdoni/circom2gnark), 
which enables verification of Circom proofs within gnark. 
Their tool parses proofs and verifier keys from Circom/SnarkJS, but its focus is different: it aims to verify proofs, 
whereas this project is focused on enabling gnark to *prove* Circom circuits.
