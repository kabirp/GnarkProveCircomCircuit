package main

import (
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Supported commands
const (
	DefineCircuitCommand = "define_circuit"
	SetupCircuitCommand  = "setup_circuit"
	ImportWitnessCommand = "import_witness"
	ProveCommand         = "prove"
	VerifyCommand        = "verify"
)
const SupportedCommands = "define_circuit,setup_circuit,import_witness,prove,verify"

// Supported usage
const (
	DefineCircuitUsage = "define_circuit <circomCircuitInPath> <gnarkCircuitOutPath>"
	SetupCircuitUsage  = "setup_circuit <gnarkCircuitInPath> <pkOutPath> <vkOutPath>"
	ImportWitnessUsage = "import_witness <circomWitnessInPath> <gnarkCircuitInPath> <wtnsOutPath> <pubInputsOutPath>"
	ProveUsage         = "prove <gnarkCircuitInPath> <pkInPath> <wtnsInPath> <proofOutPath>"
	VerifyUsage        = "verify <vkInPath> <proofInPath> <pubInputsInPath>"
)

func define_circuit(circomCircuitInPath string, gnarkCircuitOutPath string) {
	// Log function arguments
	log.Println("Defining circuit. circomCircuitInPath=" + circomCircuitInPath +
		" gnarkCircuitOutPath=" + gnarkCircuitOutPath)

	// Open input file
	circomR1csFile, err := os.Open(circomCircuitInPath)
	if err != nil {
		log.Fatalf("Failed to open circom circuit input file: %v", err)
	}

	// Sanity check the input file
	sectionTypeToMetadata := isFileValid(circomR1csFile, R1CSCircuitBinary)

	// Parse the R1CS header section
	circuit := parseR1CSHeaderSection(circomR1csFile, sectionTypeToMetadata, circomCircuitInPath)

	// Close the input file
	circomR1csFile.Close()

	// Compile the circuit - this parses the R1CS constraint section and adds the constraints
	// The gnarkConstraintSystem is the complete "circuit" with all of the R1CS constraints defined.
	// This will again open/close the circomR1csFile file. This reopening is necessary because the frontend.Circuit
	// cannot take the fileHandle in its struct, or the schema walk will complain about 'unsupported type: unsafe pointer'.
	gnarkConstraintSystem, err := frontend.Compile(ecc.BN254.ScalarField(), NewDirtyBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		log.Fatalf("Failed to compile circuit and create gnark Constraint system: %v", err)
	}

	// Create the output file, write the new gnark constraint system to it, and close the file
	outFile, err := os.Create(gnarkCircuitOutPath)
	if err != nil {
		log.Fatalf("Failed to create gnark circuit output file: %v", err)
	}
	_, err = gnarkConstraintSystem.WriteTo(outFile)
	if err != nil {
		log.Fatalf("Failed to write gnark circuit to output file: %v", err)
	}
	outFile.Close()
	log.Println("Circuit defined successfully.")
}

func setup_circuit(gnarkCircuitInPath string, pkOutPath string, vkOutPath string) {
	inFile, err := os.Open(gnarkCircuitInPath)
	if err != nil {
		log.Fatalf("Failed to open gnark circuit input file: %v", err)
	}
	var gnarkConstraintSystem constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
	gnarkConstraintSystem.ReadFrom(inFile)
	inFile.Close()

	prover_key, verifier_key, err := groth16.Setup(gnarkConstraintSystem)
	if err != nil {
		log.Fatalf("Failed to setup circuit: %v", err)
	}
	pkFile, err := os.Create(pkOutPath)
	if err != nil {
		log.Fatalf("Failed to create pk output file: %v", err)
	}
	_, err = prover_key.WriteTo(pkFile)
	if err != nil {
		log.Fatalf("Failed to write pk to output file: %v", err)
	}
	pkFile.Close()
	vkFile, err := os.Create(vkOutPath)
	if err != nil {
		log.Fatalf("Failed to create vk output file: %v", err)
	}
	_, err = verifier_key.WriteTo(vkFile)
	if err != nil {
		log.Fatalf("Failed to write vk to output file: %v", err)
	}
	vkFile.Close()
	log.Println("Setup completed successfully.")
}

func import_witness(circomWitnessInPath string, gnarkCircuitInPath string, wtnsOutPath string, pubInputsOutPath string) {
	// Log function arguments
	log.Println("Importing witness. circomWitnessInPath=" + circomWitnessInPath +
		" gnarkCircuitInPath=" + gnarkCircuitInPath +
		" wtnsOutPath=" + wtnsOutPath +
		" pubInputsOutPath=" + pubInputsOutPath)

	// Open input files
	inWitFile, err := os.Open(circomWitnessInPath)
	if err != nil {
		log.Fatalf("Failed to open circom witness file: %v", err)
	}
	defer inWitFile.Close()
	gnarkCircuitInFile, err := os.Open(gnarkCircuitInPath)
	if err != nil {
		log.Fatalf("Failed to open gnark circuit input file: %v", err)
	}
	var gnarkConstraintSystem constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
	gnarkConstraintSystem.ReadFrom(gnarkCircuitInFile)
	gnarkCircuitInFile.Close()

	nInternal, nSecret, nPublic := gnarkConstraintSystem.GetNbVariables()
	if nInternal != 0 {
		panic("The way we designed the circuit, there should be no internal variables")
	}
	totalNumVariables := nInternal + nSecret + nPublic

	// Sanity check the input file
	sectionTypeToMetadata := isFileValid(inWitFile, WitnessBinary)

	// Ensure the number of wire assignments witness file is valid w.r.t. the circuit
	nVars := parseWitnessHeader(inWitFile, sectionTypeToMetadata)
	if nVars != totalNumVariables {
		log.Fatalf("The number of variables in the witness file (%d) does not match the number of variables in the circuit (%d)", nVars, totalNumVariables)
	}

	// Create the output files
	fullWitness, publicWitness := parseWitness(inWitFile, sectionTypeToMetadata, nPublic, nSecret)

	// Sanity check that hte constraints and witness are compatible
	err = gnarkConstraintSystem.IsSolved(fullWitness)
	if err != nil {
		log.Fatalf("The witness does not satisfy the circuit: %v", err)
	}

	// Write the witness to the output file
	wtnsOutFile, err := os.Create(wtnsOutPath)
	if err != nil {
		log.Fatalf("Failed to create witness output file: %v", err)
	}
	_, err = fullWitness.WriteTo(wtnsOutFile)
	if err != nil {
		log.Fatalf("Failed to write witness to output file: %v", err)
	}
	wtnsOutFile.Close()

	// Write the public inputs to the output file
	pubInputsOutFile, err := os.Create(pubInputsOutPath)
	if err != nil {
		log.Fatalf("Failed to create public inputs output file: %v", err)
	}
	_, err = publicWitness.WriteTo(pubInputsOutFile)
	if err != nil {
		log.Fatalf("Failed to write public inputs to output file: %v", err)
	}
	pubInputsOutFile.Close()

	log.Println("Witness imported successfully.")
}

func prove(gnarkCircuitInPath, pkInPath, wtnsInPath, proofOutPath string) {
	// Load prover key, witness, and gnark circuit
	gnarkCircuitInFile, err := os.Open(gnarkCircuitInPath)
	if err != nil {
		log.Fatalf("Failed to open gnark circuit input file: %v", err)
	}
	var gnarkConstraintSystem constraint.ConstraintSystem = groth16.NewCS(ecc.BN254)
	gnarkConstraintSystem.ReadFrom(gnarkCircuitInFile)
	gnarkCircuitInFile.Close()

	pkFile, err := os.Open(pkInPath)
	if err != nil {
		log.Fatalf("Failed to open pk input file: %v", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		log.Fatalf("Failed to read pk from input file: %v", err)
	}
	pkFile.Close()

	wtnsInFile, err := os.Open(wtnsInPath)
	if err != nil {
		log.Fatalf("Failed to open witness input file: %v", err)
	}
	witness, err := witness.New(fr.Modulus())
	if err != nil {
		log.Fatalf("Failed to create new witness: %v", err)
	}
	_, err = witness.ReadFrom(wtnsInFile)
	if err != nil {
		log.Fatalf("Failed to read witness from input file: %v", err)
	}
	wtnsInFile.Close()

	// Prove the circuit
	proof, err := groth16.Prove(gnarkConstraintSystem, pk, witness)
	if err != nil {
		log.Fatalf("Failed to prove circuit: %v", err)
	}

	// Write the proof to the output file
	proofOutFile, err := os.Create(proofOutPath)
	if err != nil {
		log.Fatalf("Failed to create proof output file: %v", err)
	}
	_, err = proof.WriteTo(proofOutFile)
	if err != nil {
		log.Fatalf("Failed to write proof to output file: %v", err)
	}
	proofOutFile.Close()
	log.Println("Proof generated successfully.")
}

func verify(vkInPath string, proofInPath string, pubInputsInPath string) {
	// Load verifier key, proof, and public inputs
	vkFile, err := os.Open(vkInPath)
	if err != nil {
		log.Fatalf("Failed to open vk input file: %v", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		log.Fatalf("Failed to read vk from input file: %v", err)
	}
	vkFile.Close()

	proofFile, err := os.Open(proofInPath)
	if err != nil {
		log.Fatalf("Failed to open proof input file: %v", err)
	}
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(proofFile)
	if err != nil {
		log.Fatalf("Failed to read proof from input file: %v", err)
	}
	proofFile.Close()

	pubInputsFile, err := os.Open(pubInputsInPath)
	if err != nil {
		log.Fatalf("Failed to open public inputs input file: %v", err)
	}
	publicWitness, err := witness.New(fr.Modulus())
	if err != nil {
		log.Fatalf("Failed to create new public witness: %v", err)
	}
	_, err = publicWitness.ReadFrom(pubInputsFile)
	if err != nil {
		log.Fatalf("Failed to read public witness from input file: %v", err)
	}
	pubInputsFile.Close()

	// Verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Proof verification failed: %v", err)
	}
	log.Println("Proof verified successfully.")
}

func main() {
	command := os.Args[1]

	switch command {
	case DefineCircuitCommand:
		if len(os.Args) != 4 {
			fmt.Println("Incorrect Usage. Expected Usage: " + DefineCircuitUsage)
			os.Exit(1)
		}
		define_circuit(os.Args[2], os.Args[3])
	case SetupCircuitCommand:
		if len(os.Args) != 5 {
			fmt.Println("Incorrect Usage. Expected Usage: " + SetupCircuitUsage)
			os.Exit(1)
		}
		setup_circuit(os.Args[2], os.Args[3], os.Args[4])
	case ImportWitnessCommand:
		if len(os.Args) != 6 {
			fmt.Println("Incorrect Usage. Expected Usage: " + ImportWitnessUsage)
			os.Exit(1)
		}
		import_witness(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case ProveCommand:
		if len(os.Args) != 6 {
			fmt.Println("Incorrect Usage. Expected Usage: " + ProveUsage)
			os.Exit(1)
		}
		prove(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case VerifyCommand:
		if len(os.Args) != 5 {
			fmt.Println("Incorrect Usage. Expected Usage: " + VerifyUsage)
			os.Exit(1)
		}
		verify(os.Args[2], os.Args[3], os.Args[4])
	case "help":
		fmt.Println("Supported commands: " + SupportedCommands)
		fmt.Println("Usage:")
		fmt.Println(DefineCircuitUsage)
		fmt.Println(SetupCircuitUsage)
		fmt.Println(ImportWitnessUsage)
		fmt.Println(ProveUsage)
		fmt.Println(VerifyUsage)
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Supported commands:" + SupportedCommands)
		os.Exit(1)
	}
}
