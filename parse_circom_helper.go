// This file contains utility functions related to parsing circom binaries
// There are two binaries of interest:
// (1) R1CS specification: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md
// (2) witness specification: could not find explicit format description, but reverse-engineered.
// Note that even the R1CS specification is not perfectly documented, so some experimentation was needed to
// understand the format.
package main

import (
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"os"

	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type SectionType uint32
type BinaryType int

const (
	WitnessBinary BinaryType = iota
	R1CSCircuitBinary
)

const (
	R1CSHeaderSection      SectionType = 1
	R1CSConstraintsSection SectionType = 2
	WitnessHeaderSection   SectionType = 1
	WitnessDataSection     SectionType = 2
)

// Supporting only Groth16 and BN254 for now, so the scalar field size is 32 bytes
const scalarFieldSizeBytes = 32
const expectedR1CSVersion = 1
const expectedWitnessVersion = 2
const minR1CSSections = 3
const minWitnessSections = 2

// "r", "1F", "c", "s" = [0x72, 0x31, 0x63, 0x73] in ASCII
var r1csMagicBytes = [4]byte{0x72, 0x31, 0x63, 0x73}

// "w", "t", "n", "s" = [0x77, 0x74, 0x6e, 0x73] in ASCII
var wtnsMagicBytes = [4]byte{0x77, 0x74, 0x6e, 0x73}

// Expected Scalar Field of the BN254 curve is:
// (decimal) 21888242871839275222246405745257275088548364400416034343698204186575808495617
// (hex) 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
var BN254ScalarFieldModulusLE = [32]byte{
	0x01, 0x00, 0x00, 0xf0,
	0x93, 0xf5, 0xe1, 0x43,
	0x91, 0x70, 0xb9, 0x79,
	0x48, 0xe8, 0x33, 0x28,
	0x5d, 0x58, 0x81, 0x81,
	0xb6, 0x45, 0x50, 0xb8,
	0x29, 0xa0, 0x31, 0xe1,
	0x72, 0x4e, 0x64, 0x30,
}

type CircuitInfo struct {
	mConstraints          int
	nWires                int
	InputOutput           []frontend.Variable `gnark:"-,public"`
	Witness               []frontend.Variable `gnark:"-,secret"`
	sectionTypeToMetadata map[SectionType]SectionMetadata
	circomR1cspath        string
}

type SectionMetadata struct {
	startingOffset int64
	sectionSize    uint64
}

func checkMagicBytes(magicBytes []byte, binaryType BinaryType) {
	if len(magicBytes) != 4 {
		panic("magic bytes are not 4 bytes long")
	}
	switch binaryType {
	case R1CSCircuitBinary:
		if magicBytes[0] != r1csMagicBytes[0] ||
			magicBytes[1] != r1csMagicBytes[1] ||
			magicBytes[2] != r1csMagicBytes[2] ||
			magicBytes[3] != r1csMagicBytes[3] {
			log.Fatal("File does not start with the expected magic bytes")
		}
	case WitnessBinary:
		if magicBytes[0] != wtnsMagicBytes[0] ||
			magicBytes[1] != wtnsMagicBytes[1] ||
			magicBytes[2] != wtnsMagicBytes[2] ||
			magicBytes[3] != wtnsMagicBytes[3] {
			log.Fatal("File does not start with the expected magic bytes")
		}
	default:
		log.Fatal("Unknown file type to check magic bytes")
	}
}

func checkCircomVersion(versionBytes []byte, binaryType BinaryType) {
	if len(versionBytes) != 4 {
		panic("version bytes are not 4 bytes long")
	}
	actualVersion := int(binary.LittleEndian.Uint32(versionBytes))

	switch binaryType {
	case R1CSCircuitBinary:
		if actualVersion != expectedR1CSVersion {
			log.Fatal("R1CS file does not contain the expected version number")
		}
	case WitnessBinary:
		if actualVersion != expectedWitnessVersion {
			log.Fatal("Witness file does not contain the expected version number")
		}

	default:
		log.Fatal("Unknown file type to check version")
	}
}

func checkNSections(nSectionsBytes []byte, binaryType BinaryType) (numSections int) {
	if len(nSectionsBytes) != 4 {
		panic("number of sections bytes are not 4 bytes long")
	}
	nSections := int(binary.LittleEndian.Uint32(nSectionsBytes))
	switch binaryType {
	case R1CSCircuitBinary:
		if nSections < minR1CSSections {
			log.Fatal("R1CS file does not contain the expected number of sections")
		}
	case WitnessBinary:
		if nSections < minWitnessSections {
			log.Fatal("Witness file does not contain the expected number of sections")
		}
	default:
		log.Fatal("Unknown file type to check number of sections")
	}
	return nSections
}

func checkSeenSections(seenSections map[SectionType]SectionMetadata, binaryType BinaryType) {
	// TODO: Figure out the expected section types for witness binary
	switch binaryType {
	case R1CSCircuitBinary:
		if _, ok := seenSections[R1CSHeaderSection]; !ok {
			log.Fatal("R1CS file does not contain the header section")
		}
		if _, ok := seenSections[R1CSConstraintsSection]; !ok {
			log.Fatal("R1CS file does not contain the constraints section")
		}
	case WitnessBinary:
		if _, ok := seenSections[WitnessHeaderSection]; !ok {
			log.Fatal("Witness file does not contain the witness header section")
		}
		if _, ok := seenSections[WitnessDataSection]; !ok {
			log.Fatal("Witness file does not contain the witness data section")
		}
	default:
		log.Fatal("Unknown file type to check seen sections")
	}
}

func checkFieldModulus(fieldModulusBytes []byte) {
	if len(fieldModulusBytes) != 32 {
		log.Fatal("Field modulus bytes are not 32 bytes long")
	}
	for i := 0; i < 32; i++ {
		if fieldModulusBytes[i] != BN254ScalarFieldModulusLE[i] {
			log.Fatal("Field modulus does not match the expected value")
		}
	}
}

func isFileValid(f *os.File, binaryType BinaryType) (sectionTypeToMetadata map[SectionType]SectionMetadata) {
	currOffset := int64(0)
	buf4 := make([]byte, 4)
	buf8 := make([]byte, 8)

	// Step 1: Ensure the file starts with the magic bytes
	nBytesRead, err := f.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	checkMagicBytes(buf4, binaryType)

	// Step 2: Read the version number
	nBytesRead, err = f.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	checkCircomVersion(buf4, binaryType)

	// Step 3: Read number of sections
	nBytesRead, err = f.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nSections := checkNSections(buf4, binaryType)

	// Step 4: Read all sections and make sure no section type is duplicated
	// From spec: "If the file contain unknown section types, the format is valid, but they MUST be ignored."
	seenSections := make(map[SectionType]SectionMetadata, nSections)

	for i := 0; i < nSections; i++ {
		// Read section type
		nBytesRead, err = f.ReadAt(buf4, currOffset)
		currOffset += int64(nBytesRead)
		if err != nil {
			log.Fatal(err)
		}
		sectionType := SectionType(binary.LittleEndian.Uint32(buf4))

		// Read section size
		nBytesRead, err = f.ReadAt(buf8, currOffset)
		currOffset += int64(nBytesRead)
		if err != nil {
			log.Fatal(err)
		}
		sectionSize := int(binary.LittleEndian.Uint64(buf8))

		if _, ok := seenSections[sectionType]; ok {
			log.Fatal("File contains duplicate section types")
		}
		seenSections[sectionType] = SectionMetadata{
			startingOffset: currOffset,
			sectionSize:    uint64(sectionSize),
		}

		// Skipping Section Data
		currOffset += int64(sectionSize)
	}

	// Step 5: Make sure the file ends after all sections
	// check that we are at EOF
	nBytesRead, err = f.ReadAt(buf4, currOffset)
	if err != io.EOF && nBytesRead != 0 {
		log.Fatal("File does not end after all sections")
	}

	// Step 6: Ensure the required section types are present
	checkSeenSections(seenSections, binaryType)

	// Step 7: Return the sectionType to sectionMetadata map
	return seenSections
}

// Note: Does not close the file handle
func parseR1CSHeaderSection(circomR1csFile *os.File, sectionMetadataMap map[SectionType]SectionMetadata,
	circomR1csPath string) CircuitInfo {
	sectionMetadata := sectionMetadataMap[R1CSHeaderSection]
	currOffset := sectionMetadata.startingOffset
	buf4 := make([]byte, 4)
	buf8 := make([]byte, 8)
	buf32 := make([]byte, 32)

	// Step 1: Read field size data
	nBytesRead, err := circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	fieldSizeBytes := binary.LittleEndian.Uint32(buf4)
	if fieldSizeBytes != scalarFieldSizeBytes {
		log.Fatal("The file does not specify the expected field size")
	}
	// Step 2: Read field modulus
	nBytesRead, err = circomR1csFile.ReadAt(buf32, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	checkFieldModulus(buf32)

	// Step 3: Read number of variables
	nBytesRead, err = circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nVariables := int(binary.LittleEndian.Uint32(buf4))

	// Step 4: Read number of public outputs
	nBytesRead, err = circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nPubOut := int(binary.LittleEndian.Uint32(buf4))

	// Step 5: Read number of public inputs
	nBytesRead, err = circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nPubIn := int(binary.LittleEndian.Uint32(buf4))

	if nPubIn+nPubOut > nVariables {
		log.Fatal("The number of public inputs and outputs exceeds the number of variables")
	}

	// Step 6: Read number of private inputs
	nBytesRead, err = circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nPrivIn := int(binary.LittleEndian.Uint32(buf4))

	if nPubIn+nPubOut+nPrivIn+1 > nVariables {
		log.Fatal("The number of public inputs, outputs, private inputs and 1 (for the special 1-var) cannot" +
			" exceed the total number of variables")
	}

	// Step 7: Read number of labels
	nBytesRead, err = circomR1csFile.ReadAt(buf8, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nLabels := int(binary.LittleEndian.Uint64(buf8))

	// Check if the number of labels is equal to the number of variables
	if nLabels > nVariables {
		log.Fatal("The number of labels should never exceed the number of variables")
	}

	// Step 8: Read number of constraints
	nBytesRead, err = circomR1csFile.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	mConstraints := int(binary.LittleEndian.Uint32(buf4))

	actualSize := uint64(currOffset) - uint64(sectionMetadata.startingOffset)
	expectedSize := sectionMetadata.sectionSize
	if actualSize != expectedSize {
		log.Fatal("Header section size does not match the expected size. Actual size: " + fmt.Sprint(actualSize) + " Expected size: " + fmt.Sprint(expectedSize))
	}

	// Step 9: Return the circuit info
	io := make([]frontend.Variable, nPubIn+nPubOut)
	// all values that are not explicitly public are considered private inputs (since we will not do witness generation)
	wit := make([]frontend.Variable, nVariables-nPubIn-nPubOut-1)
	circuitInfo := CircuitInfo{
		mConstraints:          mConstraints,
		nWires:                nVariables,
		InputOutput:           io,
		Witness:               wit,
		sectionTypeToMetadata: sectionMetadataMap,
		circomR1cspath:        circomR1csPath,
	}

	log.Printf("Parsed R1CS header section: nVariables=%d, nPubIn=%d, nPubOut=%d, nLabels=%d, mConstraints=%d\n",
		nVariables, nPubIn, nPubOut, nLabels, mConstraints)

	return circuitInfo
}

func (circuit *CircuitInfo) processLinCombo(f *os.File, currOffset int64,
	builder *DirtyBuilder) (constraint.LinearExpression, int64) {
	// Read the number of linear expressions
	buf4 := make([]byte, 4)
	buf32 := make([]byte, 32)
	nBytesRead, err := f.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nTerms := int(binary.LittleEndian.Uint32(buf4))

	linExp := make([]constraint.Term, nTerms)
	for i := 0; i < nTerms; i++ {
		// Make term

		// Read the variableID
		nBytesRead, err = f.ReadAt(buf4, currOffset)
		currOffset += int64(nBytesRead)
		if err != nil {
			log.Fatal(err)
		}
		variableID := int(binary.LittleEndian.Uint32(buf4))

		// Read the coefficient
		nBytesRead, err = f.ReadAt(buf32, currOffset)
		currOffset += int64(nBytesRead)
		if err != nil {
			log.Fatal(err)
		}
		coeff := leBytesToElement(buf32)
		term := builder.MakeTerm(coeff, variableID)

		// Add the term to the linear expression
		linExp[i] = term
	}

	return linExp, currOffset
}

func (circuit *CircuitInfo) Define(api frontend.API) error {
	// Minimal Necessary Hack for what we are trying to do here, which is something this library
	// was not designed for. We are adding in our R1CS constraints *directly* and will eventually be providing our
	// own witness *directly* too.
	builder, ok := api.(*DirtyBuilder)
	if !ok {
		panic("Define was not called with DirtyBuilder")
	}

	// Open the file
	f, err := os.Open(circuit.circomR1cspath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Read the constraints section
	currOffset := circuit.sectionTypeToMetadata[R1CSConstraintsSection].startingOffset
	var A_le, B_le, C_le constraint.LinearExpression

	for i := 0; i < circuit.mConstraints; i++ {
		A_le, currOffset = circuit.processLinCombo(f, currOffset, builder)
		B_le, currOffset = circuit.processLinCombo(f, currOffset, builder)
		C_le, currOffset = circuit.processLinCombo(f, currOffset, builder)

		// Create new R-1 constraint (does not check validity of the constraint)
		constraint_id := builder.AddR1C(A_le, B_le, C_le)
		_ = constraint_id
	}

	return nil
}

// TODO: polish
func leBytesToBigInt(leBytes []byte) *big.Int {
	if len(leBytes) != 32 {
		panic("expected 32 bytes")
	}

	beBytes := make([]byte, len(leBytes))
	for i := range leBytes {
		beBytes[len(leBytes)-1-i] = leBytes[i]
	}

	// Convert to big.Int and then to fr.Element
	bi := new(big.Int).SetBytes(beBytes)

	return bi

}

// TODO: polish
func leBytesToElement(b []byte) constraint.Element {
	if len(b) != 32 {
		panic("expected 32 bytes")
	}

	bi := leBytesToBigInt(b)

	var e fr.Element
	e.SetBigInt(bi)
	var r constraint.Element
	r[0] = e[0]
	r[1] = e[1]
	r[2] = e[2]
	r[3] = e[3]
	r[4] = 0
	r[5] = 0
	return r
}

func parseWitnessHeader(file *os.File, sectionTypeToMetadata map[SectionType]SectionMetadata) (nVars int) {
	sectionMetadata := sectionTypeToMetadata[WitnessHeaderSection]
	currOffset := sectionMetadata.startingOffset
	buf4 := make([]byte, 4)
	buf32 := make([]byte, 32)

	// Step 1: Read field size data
	nBytesRead, err := file.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	fieldSizeBytes := binary.LittleEndian.Uint32(buf4)
	if fieldSizeBytes != scalarFieldSizeBytes {
		log.Fatal("The file does not specify the expected field size")
	}
	// Step 2: Read field modulus
	nBytesRead, err = file.ReadAt(buf32, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	checkFieldModulus(buf32)
	// Step 3: Read number of variables
	nBytesRead, err = file.ReadAt(buf4, currOffset)
	currOffset += int64(nBytesRead)
	if err != nil {
		log.Fatal(err)
	}
	nVars = int(binary.LittleEndian.Uint32(buf4))

	actualSize := uint64(currOffset) - uint64(sectionMetadata.startingOffset)
	expectedSize := sectionMetadata.sectionSize
	if actualSize != expectedSize {
		log.Fatal("Header section size does not match the expected size. Actual size: " + fmt.Sprint(actualSize) + " Expected size: " + fmt.Sprint(expectedSize))
	}
	// Step 4: Return the number of variables
	return nVars
}

func parseWitness(file *os.File, sectionMetadataMap map[SectionType]SectionMetadata,
	nPublic int, nSecret int) (fullWitness witness.Witness, pubWitness witness.Witness) {
	sectionMetadata := sectionMetadataMap[WitnessDataSection]
	currOffset := sectionMetadata.startingOffset
	buf32 := make([]byte, 32)
	nVars := nPublic + nSecret

	// assert that scalarFieldSizeBytes * nVars == sectionMetadata.sectionSize
	if scalarFieldSizeBytes*uint64(nVars) != sectionMetadata.sectionSize {
		log.Fatal("The number of variables does not match the expected size")
	}

	fullWitnessValues := make(chan any, nVars)
	publicWitnessValues := make(chan any, nPublic)
	for i := 0; i < nVars; i++ {
		// Read the value
		nBytesRead, err := file.ReadAt(buf32, currOffset)
		currOffset += int64(nBytesRead)
		if err != nil {
			log.Fatal(err)
		}
		value := leBytesToBigInt(buf32)
		if i == 0 {
			continue //skip the first value
		}
		fullWitnessValues <- value
		if i < nPublic {
			publicWitnessValues <- value
		}
	}
	// Close the channels
	close(fullWitnessValues)
	close(publicWitnessValues)

	// Create a new witness
	fullWitness, err := witness.New(fr.Modulus())
	if err != nil {
		log.Fatal(err)
	}

	// Create the public witness
	pubWitness, err = witness.New(fr.Modulus())
	if err != nil {
		log.Fatal(err)
	}

	// Set the values in the witness
	// We subtract one to account for the fact that the first value is hardcoded to 1 in R1CS
	// See the code in constraint/bn254/solver.go#newSolver to understand this.
	err = fullWitness.Fill(nPublic-1, nSecret, fullWitnessValues)
	if err != nil {
		log.Fatal(err)
	}

	// Set the values in the public witness
	// We subtract one to account for the fact that the first value is hardcoded to 1 in R1CS
	// See the code in constraint/bn254/solver.go#newSolver to understand this.
	err = pubWitness.Fill(nPublic-1, 0, publicWitnessValues)
	if err != nil {
		log.Fatal(err)
	}

	return fullWitness, pubWitness
}
