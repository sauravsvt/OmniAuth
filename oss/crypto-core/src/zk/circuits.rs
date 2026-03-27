//! ZK Circuit Definitions for Identity Claims
//!
//! These circuits implement the core identity predicates for OmniAuth 2.0.
//! Each circuit proves a property about private data without revealing it.
//! 
//! SECURITY: All circuits include bit-length constraints to prevent 
//! finite field wrap-around attacks on the BN254 scalar field (~254 bits).
//! Slack variables are constrained via bit decomposition to ensure they
//! represent actual non-negative integers within a bounded range.

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

// ============================================================================
// Bit Decomposition Helper
// ============================================================================

/// Constrains `var` to be a non-negative integer representable in `num_bits` bits.
///
/// Without this, a "negative" field difference (e.g., `5 - 10` in a prime field)
/// wraps around to `p - 5`, which is a huge value that still satisfies algebraic
/// equality constraints. By decomposing into bits and reconstructing, we guarantee
/// the value fits in `[0, 2^num_bits)`.
fn enforce_non_negative<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    var: &FpVar<F>,
    num_bits: usize,
) -> Result<(), SynthesisError> {
    let value = var.value().unwrap_or_default();
    let value_bigint = value.into_bigint();
    let limbs = value_bigint.as_ref();

    let mut reconstructed = FpVar::<F>::zero();
    let mut power_of_two = F::one();

    for i in 0..num_bits {
        let bit_val = (limbs[i / 64] >> (i % 64)) & 1 == 1;

        let bit = FpVar::<F>::new_witness(cs.clone(), || {
            Ok(if bit_val { F::one() } else { F::zero() })
        })?;

        // Constrain bit to be 0 or 1: bit * (1 - bit) = 0
        let one_minus_bit = FpVar::Constant(F::one()) - &bit;
        let product = &bit * &one_minus_bit;
        product.enforce_equal(&FpVar::Constant(F::zero()))?;

        reconstructed += &bit * FpVar::Constant(power_of_two);
        power_of_two.double_in_place();
    }

    // The original value must equal the reconstructed value from bits,
    // proving it fits in [0, 2^num_bits)
    reconstructed.enforce_equal(var)?;

    Ok(())
}

// ============================================================================
// AgeProofCircuit
// ============================================================================
/// Proves that a user's age is >= a given threshold without revealing their birth date.
///
/// # Public Inputs
/// - `current_date`: The current date (Unix timestamp or YYYYMMDD as u64)
/// - `age_threshold`: The minimum age in the same units as dates
///
/// # Private Inputs  
/// - `birth_date`: The user's actual birth date (hidden from verifier)
///
/// # Constraint
/// `birth_date + age_threshold <= current_date`
///
/// # Security
/// - Slack variable is bit-decomposed to 64 bits, preventing field wrap-around attacks
#[derive(Clone)]
pub struct AgeProofCircuit<F: PrimeField> {
    pub current_date: Option<u64>,
    pub age_threshold: Option<u64>,
    pub birth_date: Option<u64>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for AgeProofCircuit<F> {
    fn default() -> Self {
        Self {
            current_date: None,
            age_threshold: None,
            birth_date: None,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> AgeProofCircuit<F> {
    /// Creates a new AgeProofCircuit with the given inputs.
    pub fn new(current_date: u64, age_threshold: u64, birth_date: u64) -> Self {
        Self {
            current_date: Some(current_date),
            age_threshold: Some(age_threshold),
            birth_date: Some(birth_date),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AgeProofCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let birth_date_var = FpVar::<F>::new_witness(cs.clone(), || {
            Ok(F::from(self.birth_date.ok_or(SynthesisError::AssignmentMissing)?))
        })?;

        let current_date_var = FpVar::<F>::new_input(cs.clone(), || {
            Ok(F::from(self.current_date.ok_or(SynthesisError::AssignmentMissing)?))
        })?;
        
        let threshold_var = FpVar::<F>::new_input(cs.clone(), || {
            Ok(F::from(self.age_threshold.ok_or(SynthesisError::AssignmentMissing)?))
        })?;

        // Core logic: prove current_date >= birth_date + threshold
        // Rearranged: slack = current_date - birth_date - threshold, slack >= 0
        let min_required_date = &birth_date_var + &threshold_var;
        
        let slack = FpVar::<F>::new_witness(cs.clone(), || {
            let current = F::from(self.current_date.ok_or(SynthesisError::AssignmentMissing)?);
            let birth = F::from(self.birth_date.ok_or(SynthesisError::AssignmentMissing)?);
            let threshold = F::from(self.age_threshold.ok_or(SynthesisError::AssignmentMissing)?);
            Ok(current - birth - threshold)
        })?;
        
        let reconstructed = &min_required_date + &slack;
        reconstructed.enforce_equal(&current_date_var)?;

        // CRITICAL: Constrain slack to be a genuine non-negative integer.
        // 64 bits is more than sufficient for date arithmetic.
        enforce_non_negative(cs, &slack, 64)?;

        Ok(())
    }
}

// ============================================================================
// RangeProofCircuit
// ============================================================================
/// Proves a value lies within a range [min, max] without revealing the value.
///
/// # Public Inputs
/// - `min`: Lower bound (inclusive)
/// - `max`: Upper bound (inclusive)
///
/// # Private Inputs
/// - `value`: The secret value to range-check
///
/// # Constraint
/// `min <= value <= max`
///
/// # Security
/// - Both slack variables are bit-decomposed to 64 bits, preventing field wrap-around
#[derive(Clone)]
pub struct RangeProofCircuit<F: PrimeField> {
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub value: Option<u64>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for RangeProofCircuit<F> {
    fn default() -> Self {
        Self {
            min: None,
            max: None,
            value: None,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> RangeProofCircuit<F> {
    pub fn new(min: u64, max: u64, value: u64) -> Self {
        Self {
            min: Some(min),
            max: Some(max),
            value: Some(value),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for RangeProofCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let value_var = FpVar::<F>::new_witness(cs.clone(), || {
            Ok(F::from(self.value.ok_or(SynthesisError::AssignmentMissing)?))
        })?;

        let min_var = FpVar::<F>::new_input(cs.clone(), || {
            Ok(F::from(self.min.ok_or(SynthesisError::AssignmentMissing)?))
        })?;
        
        let max_var = FpVar::<F>::new_input(cs.clone(), || {
            Ok(F::from(self.max.ok_or(SynthesisError::AssignmentMissing)?))
        })?;

        // Enforce: value >= min via slack_lower = value - min >= 0
        let slack_lower = FpVar::<F>::new_witness(cs.clone(), || {
            let v = F::from(self.value.ok_or(SynthesisError::AssignmentMissing)?);
            let m = F::from(self.min.ok_or(SynthesisError::AssignmentMissing)?);
            Ok(v - m)
        })?;
        let reconstructed_value = &min_var + &slack_lower;
        reconstructed_value.enforce_equal(&value_var)?;
        enforce_non_negative(cs.clone(), &slack_lower, 64)?;
        
        // Enforce: value <= max via slack_upper = max - value >= 0
        let slack_upper = FpVar::<F>::new_witness(cs.clone(), || {
            let v = F::from(self.value.ok_or(SynthesisError::AssignmentMissing)?);
            let m = F::from(self.max.ok_or(SynthesisError::AssignmentMissing)?);
            Ok(m - v)
        })?;
        let reconstructed_max = &value_var + &slack_upper;
        reconstructed_max.enforce_equal(&max_var)?;
        enforce_non_negative(cs, &slack_upper, 64)?;

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    // --- AgeProofCircuit tests ---

    #[test]
    fn test_age_circuit_satisfiable_adult() {
        // birth=2000, current=2025, threshold=18 -> 2000+18=2018 <= 2025
        let circuit = AgeProofCircuit::<Fr>::new(2025, 18, 2000);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap(), "Adult should satisfy age constraint");
        println!("Age circuit constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_age_circuit_exactly_at_threshold() {
        // birth=2007, current=2025, threshold=18 -> 2007+18=2025 == 2025 (slack=0)
        let circuit = AgeProofCircuit::<Fr>::new(2025, 18, 2007);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap(), "Exactly at threshold should satisfy");
    }

    #[test]
    fn test_age_circuit_rejects_minor() {
        // birth=2015, current=2025, threshold=18 -> 2015+18=2033 > 2025
        // slack would be 2025-2015-18 = -8, which wraps in the field.
        // Bit decomposition MUST reject this.
        let circuit = AgeProofCircuit::<Fr>::new(2025, 18, 2015);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(!cs.is_satisfied().unwrap(), "Minor MUST NOT satisfy age constraint");
    }

    #[test]
    fn test_age_circuit_rejects_one_year_short() {
        // birth=2008, current=2025, threshold=18 -> 2008+18=2026 > 2025
        // slack = -1 (wraps in field, bit decomposition rejects)
        let circuit = AgeProofCircuit::<Fr>::new(2025, 18, 2008);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(!cs.is_satisfied().unwrap(), "One year short MUST NOT satisfy");
    }

    // --- RangeProofCircuit tests ---

    #[test]
    fn test_range_circuit_in_bounds() {
        let circuit = RangeProofCircuit::<Fr>::new(100, 200, 150);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap(), "Value 150 should be in range [100, 200]");
    }

    #[test]
    fn test_range_circuit_at_bounds() {
        let circuit_min = RangeProofCircuit::<Fr>::new(100, 200, 100);
        let cs_min = ConstraintSystem::<Fr>::new_ref();
        circuit_min.generate_constraints(cs_min.clone()).unwrap();
        assert!(cs_min.is_satisfied().unwrap(), "Value 100 should be in range [100, 200]");

        let circuit_max = RangeProofCircuit::<Fr>::new(100, 200, 200);
        let cs_max = ConstraintSystem::<Fr>::new_ref();
        circuit_max.generate_constraints(cs_max.clone()).unwrap();
        assert!(cs_max.is_satisfied().unwrap(), "Value 200 should be in range [100, 200]");
    }

    #[test]
    fn test_range_circuit_rejects_below_min() {
        // value=99 < min=100 -> slack_lower = 99-100 = -1 (wraps, rejected by bit decomp)
        let circuit = RangeProofCircuit::<Fr>::new(100, 200, 99);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(!cs.is_satisfied().unwrap(), "Value 99 MUST NOT be in range [100, 200]");
    }

    #[test]
    fn test_range_circuit_rejects_above_max() {
        // value=201 > max=200 -> slack_upper = 200-201 = -1 (wraps, rejected by bit decomp)
        let circuit = RangeProofCircuit::<Fr>::new(100, 200, 201);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(!cs.is_satisfied().unwrap(), "Value 201 MUST NOT be in range [100, 200]");
    }

    #[test]
    fn test_range_circuit_rejects_far_out_of_range() {
        let circuit = RangeProofCircuit::<Fr>::new(100, 200, 1000);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(!cs.is_satisfied().unwrap(), "Value 1000 MUST NOT be in range [100, 200]");
    }

    #[test]
    fn test_range_circuit_single_value_range() {
        // Range [42, 42] should only accept exactly 42
        let circuit_ok = RangeProofCircuit::<Fr>::new(42, 42, 42);
        let cs_ok = ConstraintSystem::<Fr>::new_ref();
        circuit_ok.generate_constraints(cs_ok.clone()).unwrap();
        assert!(cs_ok.is_satisfied().unwrap(), "Value 42 should be in range [42, 42]");

        let circuit_bad = RangeProofCircuit::<Fr>::new(42, 42, 43);
        let cs_bad = ConstraintSystem::<Fr>::new_ref();
        circuit_bad.generate_constraints(cs_bad.clone()).unwrap();
        assert!(!cs_bad.is_satisfied().unwrap(), "Value 43 MUST NOT be in range [42, 42]");
    }
}
