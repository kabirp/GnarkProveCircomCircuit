// Minimal necessary hack to use gnark's R1CS builder
// REQUIRES builder struct in github.com/consensys/gnark/frontend/cs/r1cs to have:
// 1. a field of type constraint.R1CS named "cs"
// 2. a field of type constraint.BlueprintID named "genericGate"
// 3. an internal kvstore (key-value store) that implements the following methods:
//   - SetKeyValue(key, value any)
//   - GetKeyValue(key any) any
package main

import (
	"log"
	"math/big"
	"reflect"
	"unsafe"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type DirtyBuilder struct {
	wrappedBuilder frontend.Builder
}

func NewDirtyBuilder(field *big.Int, config frontend.CompileConfig) (frontend.Builder, error) {
	wrappedBuilder, err := r1cs.NewBuilder(field, config)
	if err != nil {
		return nil, err
	}
	return &DirtyBuilder{wrappedBuilder: wrappedBuilder}, nil
}

// This is an unsafe hack because the gnark library does not export the
// constraint.R1CS object, but we need to access it to add constraints
// to the R1CS object. This is a workaround to access the unexported field.
// This is necessary because we are trying to use the gnark library in a way it did not intend.
func getCS(b interface{}) constraint.R1CS {
	val := reflect.ValueOf(b).Elem()
	field := val.FieldByName("cs")
	// Allow reading an unexported field:
	ptrToField := unsafe.Pointer(field.UnsafeAddr())
	r1cs, ok := reflect.NewAt(field.Type(), ptrToField).Elem().Interface().(constraint.R1CS)
	if !ok {
		log.Fatalf("failed to assert type to constraint.R1CS")
	}
	return r1cs
}

// This is the same hack as above, but for the genericGate field
func getGenericGate(b interface{}) constraint.BlueprintID {
	val := reflect.ValueOf(b).Elem()
	field := val.FieldByName("genericGate")
	// Allow reading an unexported field:
	ptrToField := unsafe.Pointer(field.UnsafeAddr())
	genericGate, ok := reflect.NewAt(field.Type(), ptrToField).Elem().Interface().(constraint.BlueprintID)
	if !ok {
		log.Fatalf("failed to assert type to constraint.Gate")
	}
	return genericGate
}

func (dirtyBuilder *DirtyBuilder) AddR1C(l, r, o frontend.Variable) int {
	r1c := dirtyBuilder.newR1C(l, r, o)
	builder_cs := getCS(dirtyBuilder.wrappedBuilder)
	builder_genericGate := getGenericGate(dirtyBuilder.wrappedBuilder)
	return builder_cs.AddR1C(r1c, builder_genericGate)
}

func (dirtyBuilder *DirtyBuilder) MakeTerm(coeff constraint.Element, variableID int) constraint.Term {
	builder_cs := getCS(dirtyBuilder.wrappedBuilder)
	return builder_cs.MakeTerm(coeff, variableID)
}

func (dirtyBuilder *DirtyBuilder) PrintR1CS() {
	builder_cs := getCS(dirtyBuilder.wrappedBuilder)
	constraints := builder_cs.GetR1Cs()

	for _, r1c := range constraints {
		log.Println(r1c.String(builder_cs))
	}
}

// More hacks for the internal kvstore inside the wrappedBuilder object.

// Ensure DirtyBuilder implements the kvstore methods by forwarding calls.
func (db *DirtyBuilder) SetKeyValue(key, value any) {
	// We know that the underlying builder implements:
	//   SetKeyValue(key, value any)
	type storeInterface interface {
		SetKeyValue(key, value any)
	}
	// Assert the underlying builder implements storeInterface and call it.
	si := db.wrappedBuilder.(storeInterface)
	si.SetKeyValue(key, value)
}

func (db *DirtyBuilder) GetKeyValue(key any) any {
	type storeInterface interface {
		GetKeyValue(key any) any
	}
	si := db.wrappedBuilder.(storeInterface)
	return si.GetKeyValue(key)
}

// This code is copy pasted from github.com/consensys/gnark/frontend/cs/r1cs/builder.go
// Some lines, however, have been commented out.
// newR1C clones the linear expression associated with the Variables (to avoid offsetting the ID multiple time)
// and return a R1C
func (dirtyBuilder *DirtyBuilder) newR1C(l, r, o frontend.Variable) constraint.R1C {
	L := dirtyBuilder.getLinearExpression(l)
	R := dirtyBuilder.getLinearExpression(r)
	O := dirtyBuilder.getLinearExpression(o)

	// Kabir: No switching! Want this R1CS to be the same! (Would matter for using the same proving / verifying key)
	//
	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	// if len(L) > len(R) {
	// 	// TODO @gbotrel shouldn't we do the opposite? Code doesn't match comment.
	// 	L, R = R, L
	// }

	return constraint.R1C{L: L, R: R, O: O}
}

func (dirtyBuilder *DirtyBuilder) getLinearExpression(_l interface{}) constraint.LinearExpression {
	var L constraint.LinearExpression
	switch tl := _l.(type) {
	// Kabir: can't use internal libraries, so must use constraint.LinearExpression
	//
	// case expr.LinearExpression:
	// 	if len(tl) == 1 && tl[0].VID == 0 {
	// 		if tl[0].Coeff.IsZero() {
	// 			return builder.cZero
	// 		} else if tl[0].Coeff == builder.tOne {
	// 			return builder.cOne
	// 		}
	// 	}
	// 	L = make(constraint.LinearExpression, 0, len(tl))
	// 	for _, t := range tl {
	// 		L = append(L, builder.cs.MakeTerm(t.Coeff, t.VID))
	// 	}
	case constraint.LinearExpression:
		L = tl
	default:
		panic("invalid input for getLinearExpression") // sanity check
	}
	return L
}
