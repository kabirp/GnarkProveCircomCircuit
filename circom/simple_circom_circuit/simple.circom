pragma circom 2.0.0;

template Simple() {
    // Inputs
    signal input x;
    signal input y;

    // Outputs
    signal output out;

    // Intermediate signals
    signal x_plus_1;
    signal x_plus_1_sq;
    signal x_plus_1_cubed;
    signal y_sq;
    signal y_quad;

    // Compute (x + 1)
    x_plus_1 <== x + 1;

    // Compute (x + 1)^2
    x_plus_1_sq <== x_plus_1 * x_plus_1;

    // Compute (x + 1)^3
    x_plus_1_cubed <== x_plus_1_sq * x_plus_1;

    // Compute y^2
    y_sq <== y * y;

    // Compute y^4
    y_quad <== y_sq * y_sq;

    // Compute (x + 1)^3 + y^4 + 8
    out <== x_plus_1_cubed + y_quad + 8;
}

component main = Simple();

