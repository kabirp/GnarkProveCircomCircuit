package main

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// Boilerplate wrapper code to implement the Builder interface

// BUILDER

func (builder *DirtyBuilder) Compile() (constraint.ConstraintSystem, error) {
	return builder.wrappedBuilder.Compile()
}
func (builder *DirtyBuilder) PublicVariable(schema schema.LeafInfo) frontend.Variable {
	return builder.wrappedBuilder.PublicVariable(schema)
}
func (builder *DirtyBuilder) SecretVariable(schema schema.LeafInfo) frontend.Variable {
	return builder.wrappedBuilder.SecretVariable(schema)
}

// COMPILER

func (builder *DirtyBuilder) AddBlueprint(b constraint.Blueprint) constraint.BlueprintID {
	return builder.wrappedBuilder.AddBlueprint(b)
}
func (builder *DirtyBuilder) AddInstruction(bID constraint.BlueprintID, calldata []uint32) []uint32 {
	return builder.wrappedBuilder.AddInstruction(bID, calldata)
}
func (builder *DirtyBuilder) MarkBoolean(v frontend.Variable) {
	builder.wrappedBuilder.MarkBoolean(v)
}
func (builder *DirtyBuilder) IsBoolean(v frontend.Variable) bool {
	return builder.wrappedBuilder.IsBoolean(v)
}
func (builder *DirtyBuilder) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	return builder.wrappedBuilder.NewHint(f, nbOutputs, inputs...)
}
func (builder *DirtyBuilder) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	return builder.wrappedBuilder.ConstantValue(v)
}
func (builder *DirtyBuilder) Field() *big.Int {
	return builder.wrappedBuilder.Field()
}
func (builder *DirtyBuilder) FieldBitLen() int {
	return builder.wrappedBuilder.FieldBitLen()
}
func (builder *DirtyBuilder) Defer(cb func(api frontend.API) error) {
	builder.wrappedBuilder.Defer(cb)
}
func (builder *DirtyBuilder) InternalVariable(wireID uint32) frontend.Variable {
	return builder.wrappedBuilder.InternalVariable(wireID)
}
func (builder *DirtyBuilder) ToCanonicalVariable(v frontend.Variable) frontend.CanonicalVariable {
	return builder.wrappedBuilder.ToCanonicalVariable(v)
}
func (builder *DirtyBuilder) SetGkrInfo(gkrInfo constraint.GkrInfo) error {
	return builder.wrappedBuilder.SetGkrInfo(gkrInfo)
}

// API

func (builder *DirtyBuilder) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Add(i1, i2, in...)
}
func (builder *DirtyBuilder) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.MulAcc(a, b, c)
}
func (builder *DirtyBuilder) Neg(i1 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Neg(i1)
}
func (builder *DirtyBuilder) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Sub(i1, i2, in...)
}
func (builder *DirtyBuilder) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Mul(i1, i2, in...)
}
func (builder *DirtyBuilder) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.DivUnchecked(i1, i2)
}
func (builder *DirtyBuilder) Div(i1, i2 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Div(i1, i2)
}
func (builder *DirtyBuilder) Inverse(i1 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Inverse(i1)
}
func (builder *DirtyBuilder) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	return builder.wrappedBuilder.ToBinary(i1, n...)
}
func (builder *DirtyBuilder) FromBinary(b ...frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.FromBinary(b...)
}
func (builder *DirtyBuilder) Xor(a, b frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Xor(a, b)
}
func (builder *DirtyBuilder) Or(a, b frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Or(a, b)
}
func (builder *DirtyBuilder) And(a, b frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.And(a, b)
}
func (builder *DirtyBuilder) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Select(b, i1, i2)
}
func (builder *DirtyBuilder) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Lookup2(b0, b1, i0, i1, i2, i3)
}
func (builder *DirtyBuilder) IsZero(i1 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.IsZero(i1)
}
func (builder *DirtyBuilder) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	return builder.wrappedBuilder.Cmp(i1, i2)
}
func (builder *DirtyBuilder) AssertIsEqual(i1, i2 frontend.Variable) {
	builder.wrappedBuilder.AssertIsEqual(i1, i2)
}
func (builder *DirtyBuilder) AssertIsDifferent(i1, i2 frontend.Variable) {
	builder.wrappedBuilder.AssertIsDifferent(i1, i2)
}
func (builder *DirtyBuilder) AssertIsBoolean(i1 frontend.Variable) {
	builder.wrappedBuilder.AssertIsBoolean(i1)
}
func (builder *DirtyBuilder) AssertIsCrumb(i1 frontend.Variable) {
	builder.wrappedBuilder.AssertIsCrumb(i1)
}
func (builder *DirtyBuilder) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	builder.wrappedBuilder.AssertIsLessOrEqual(v, bound)
}
func (builder *DirtyBuilder) Println(a ...frontend.Variable) {
	builder.wrappedBuilder.Println(a...)
}
func (builder *DirtyBuilder) Compiler() frontend.Compiler {
	return builder.wrappedBuilder.Compiler()
}

// Already declared
// func (builder *DirtyBuilder) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
// 	return builder.wrappedBuilder.NewHint(f, nbOutputs, inputs...)
// }
// func (builder *DirtyBuilder) ConstantValue(v frontend.Variable) (*big.Int, bool) {
// 	return builder.wrappedBuilder.ConstantValue(v)
// }
