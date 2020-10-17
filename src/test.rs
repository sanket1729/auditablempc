use algebra_core::{Field, PrimeField};
extern crate rand;

use algebra::bls12_381::Fr;
use algebra_core::biginteger::BigInteger256;
use algebra_core::PairingEngine;
use algebra_core::{One, Zero};
use r1cs_core::{
    ConstraintSynthesizer, ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use rand::Rng;

#[derive(Clone)]
struct Circuit<F: Field> {
    a: Option<F>, //witness
    b: Option<F>, //witness
    d: Option<F>, //client input
    e: Option<F>, //client input
    f: Option<F>, //server output
    stmt_inputs: Option<Vec<F>>,
    num_constraints: usize,
    num_variables: usize,
    num_input_variables: usize,
}

#[derive(Clone)]
struct Compare<'a, F: Field> {
    n: usize,
    bids_as_feild_elems: Vec<F>,
    bids: Vec<u64>,
    diff_bin: Vec<Vec<F>>,
    diff_vec: Vec<F>,
    res: Vec<F>,
    res_val: Vec<F>,
    a_res: Vec<F>,
    b_res: Vec<F>,
    powers_of_two: &'a Vec<F>,
    powers_of_two_as_u64: &'a Vec<u64>,
}

#[derive(Clone)]
struct LogRank<'a, F: Field> {
    k: usize,
    di: Vec<Vec<F>>,
    ni: Vec<Vec<F>>,
    d_as_u64: Vec<Vec<u64>>,
    n_as_u64: Vec<Vec<u64>>,
    ac: Vec<F>,
    bd: Vec<F>,
    frc: Vec<F>,
    frc_ext: Vec<F>,
    frc_ext2: Vec<F>,
    ei: Vec<F>,
    vn: Vec<F>,
    n1n2: Vec<F>,
    n1n2ac: Vec<F>,
    vd: Vec<F>,
    bd2: Vec<F>,
    vi: Vec<F>,
    vi_ext: Vec<F>,
    vi_ext2: Vec<F>,
    e: F,
    v: F,
    d: F,
    dmi: F,
    chi0: F,
    chi0_ext: F,
    chi0_ext2: F,
    chi: F,
    chi_ext: F,
    chi_ext2: F,
    bin_vals: Vec<Vec<F>>,
    powers_of_two: &'a Vec<F>,
    powers_of_two_as_u64: &'a Vec<u64>,
}

impl<'a> LogRank<'a, Fr> {
    pub(crate) fn new(
        k: usize,
        di: Vec<Vec<Fr>>,
        ni: Vec<Vec<Fr>>,
        d_as_u64: Vec<Vec<u64>>,
        n_as_u64: Vec<Vec<u64>>,
        powers_of_two: &'a Vec<Fr>,
        powers_of_two_as_u64: &'a Vec<u64>,
    ) -> Self {
        Self {
            k: k,
            di: di,
            ni: ni,
            d_as_u64: d_as_u64,
            n_as_u64: n_as_u64,
            ac: vec![],
            bd: vec![],
            frc: vec![],
            frc_ext: vec![],
            frc_ext2: vec![],
            ei: vec![],
            vn: vec![],
            n1n2: vec![],
            n1n2ac: vec![],
            vd: vec![],
            bd2: vec![],
            vi: vec![],
            vi_ext: vec![],
            vi_ext2: vec![],
            e: Fr::zero(),
            v: Fr::zero(),
            d: Fr::zero(),
            dmi: Fr::zero(),
            chi0: Fr::zero(),
            chi0_ext: Fr::zero(),
            chi0_ext2: Fr::zero(),
            chi: Fr::zero(),
            chi_ext: Fr::zero(),
            chi_ext2: Fr::zero(),
            bin_vals: vec![],
            powers_of_two: powers_of_two,
            powers_of_two_as_u64: powers_of_two_as_u64,
        }
    }

    fn bin_solver(&self, num_bits: Option<usize>, val: u64) -> Vec<Fr> {
        let num_bits = num_bits.unwrap_or(self.k + 1) + 1;
        let mut val_bits = vec![Fr::zero(); num_bits];
        let mut j = 0;
        let mut val = val;
        while val > 0 {
            let last_bit = val % 2;
            val = val / 2u64;
            if last_bit == 1 {
                val_bits[j] = Fr::one();
            }
            j += 1;
        }
        val_bits
    }

    pub(crate) fn solve(&mut self) {
        let num_samples = self.di[0].len();
        let pow_2k = 2u64.pow(self.k as u32);
        let mut e = 0;
        let mut v = 0;
        let mut d = 0;
        for i in 0..num_samples {
            //scale for floating point operations
            // for j in 0..2 {
            //     self.di[j][i] *= pow_2k_as_f;
            //     self.ni[j][i] *= pow_2k_as_f;
            //     self.d_as_u64[j][i] *= pow_2k;
            //     self.n_as_u64[j][i] *= pow_2k;
            // }
            //line 2 and line 3
            let ac = self.d_as_u64[0][i] + self.d_as_u64[1][i];
            let bd = self.n_as_u64[0][i] + self.n_as_u64[1][i];
            d += self.d_as_u64[0][i];
            self.ac.push(self.di[0][i] + self.di[1][i]);
            self.bd.push(self.ni[0][i] + self.ni[1][i]);

            //line 4
            let frc = ac * pow_2k / bd;
            assert!(ac < bd);
            let frc_ext = bd - (ac * 2u64.pow(self.k as u32) - bd * frc);
            let frc_ext2 = bd + (ac * 2u64.pow(self.k as u32) - bd * frc);
            self.frc.push(Fr::from_repr(BigInteger256::from(frc)));
            self.frc_ext
                .push(Fr::from_repr(BigInteger256::from(frc_ext)));
            self.frc_ext2
                .push(Fr::from_repr(BigInteger256::from(frc_ext2)));
            self.bin_vals
                .push(self.bin_solver(Some(actual_bits(bd)), frc_ext));
            self.bin_vals
                .push(self.bin_solver(Some(actual_bits(bd)), frc_ext2));

            //line 5
            let ei = frc * self.n_as_u64[0][i];
            e += ei;
            self.ei.push(Fr::from_repr(BigInteger256::from(ei)));

            //line 6
            let n1n2 = self.n_as_u64[0][i] * self.n_as_u64[1][i] ;
            self.n1n2.push(Fr::from_repr(BigInteger256::from(n1n2)));

            let n1n2ac = n1n2 * ac ;
            self.n1n2ac.push(Fr::from_repr(BigInteger256::from(n1n2ac)));

            let vn = n1n2ac * (bd - ac) ;
            self.vn.push(Fr::from_repr(BigInteger256::from(vn)));

            //line 7
            let bd2 = bd * bd ;
            self.bd2.push(Fr::from_repr(BigInteger256::from(bd2)));

            let vd = bd2 * (bd - 1) ;
            self.vd.push(Fr::from_repr(BigInteger256::from(vd)));

            //line 8
            let vi = vn * pow_2k / vd;
            v += vi;
            let vi_ext = vd - (vn * pow_2k - vi * vd);
            let vi_ext2 = vd + vn * pow_2k - vi * vd;
            self.vi.push(Fr::from_repr(BigInteger256::from(vi)));
            self.vi_ext.push(Fr::from_repr(BigInteger256::from(vi_ext)));
            self.bin_vals
                .push(self.bin_solver(Some(actual_bits(vd)), vi_ext));
            self.vi_ext2.push(Fr::from_repr(BigInteger256::from(vi_ext2)));
            self.bin_vals
                .push(self.bin_solver(Some(actual_bits(vd)), vi_ext2));
        }
        // Sum up all the values
        self.e = Fr::from_repr(BigInteger256::from(e));
        self.v = Fr::from_repr(BigInteger256::from(v));
        self.d = Fr::from_repr(BigInteger256::from(d));

        // line 3: Alg3
        let dmi = pow_2k*d - e;
        self.dmi = Fr::from_repr(BigInteger256::from(dmi));

        //line 4: Alg3
        let chi0 = dmi * pow_2k / v;
        let chi0_ext = v - (dmi * pow_2k - chi0*v);
        let chi0_ext2 = v + (dmi * pow_2k - chi0*v);
        self.chi0 = Fr::from_repr(BigInteger256::from(chi0));
        self.chi0_ext = Fr::from_repr(BigInteger256::from(chi0_ext));
        self.bin_vals
            .push(self.bin_solver(Some(actual_bits(v)), chi0_ext));
        self.chi0_ext2 = Fr::from_repr(BigInteger256::from(chi0_ext2));
        self.bin_vals
            .push(self.bin_solver(Some(actual_bits(v)), chi0_ext2));

        //line 5: Alg3
        let chi = chi0 * dmi / pow_2k;
        let chi_ext = pow_2k + pow_2k*chi - chi0 * dmi;
        let chi_ext2 = pow_2k + chi0 * dmi - pow_2k*chi;
        self.chi = Fr::from_repr(BigInteger256::from(chi));
        self.chi_ext = Fr::from_repr(BigInteger256::from(chi_ext));
        self.bin_vals
        .push(self.bin_solver(None, chi_ext));
        self.chi_ext2 = Fr::from_repr(BigInteger256::from(chi_ext2));
        self.bin_vals
        .push(self.bin_solver(None, chi_ext2));
    }
}

fn nearest_pow_of_two(inp: usize) -> usize {
    let mut ret = 1;
    while ret < inp {
        ret = ret * 2;
    }
    ret
}

fn actual_bits(num: u64) -> usize {
    (64 - num.leading_zeros()) as usize
}
impl<'a, ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for LogRank<'a, ConstraintF> {
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        fn bin_gadget<F: Field, CS: ConstraintSystem<F>>(
            cs: &mut CS,
            bin_vals: Vec<F>,
            num: Variable,
            powers_of_two: &Vec<F>,
        ) -> Result<(), SynthesisError> {
            let mut gather = LinearCombination::<F>::zero();
            for i in 0..bin_vals.len() {
                let bit = cs.alloc(|| format!("bit {}", i), || Ok(bin_vals[i]))?;
                gather = gather + (powers_of_two[i], bit);
                cs.enforce(
                    || format!("Variable {}: 1 or 0", i),
                    |lc| lc + bit,
                    |lc| lc + CS::one() - bit,
                    |lc| lc,
                );
            }
            cs.enforce(|| "Sum", |l| l, |l| l, |lc| lc + gather - num);
            Ok(())
        }

        let num_samples = self.di[0].len();
        let pow_2k_as_f = self.powers_of_two[self.k];

        let mut gather_e = LinearCombination::<ConstraintF>::zero();
        let mut gather_v = LinearCombination::<ConstraintF>::zero();
        let mut gather_d = LinearCombination::<ConstraintF>::zero();
        let total_num_inputs = nearest_pow_of_two(4 * num_samples + 2);
        for j in 0..(total_num_inputs - (4 * num_samples + 2)) {
            let _inp = cs.alloc_input(|| format!("temp {}", j), || Ok(self.di[0][0]))?;
        }
        let mut bin_val_iter = 0;
        for i in 0..num_samples {
            // Allocated inputs
            let di0 = cs.alloc_input(|| format!("di0 {}", i), || Ok(self.di[0][i]))?;
            gather_d = gather_d + di0;
            let di1 = cs.alloc_input(|| format!("di1 {}", i), || Ok(self.di[1][i]))?;
            let ni0 = cs.alloc_input(|| format!("ni0 {}", i), || Ok(self.ni[0][i]))?;
            let ni1 = cs.alloc_input(|| format!("ni1 {}", i), || Ok(self.ni[1][i]))?;

            // Witness elements: Line 2 and 3
            let ac = cs.alloc(|| format!("ac {}", i), || Ok(self.ac[i]))?;
            let bd = cs.alloc(|| format!("bd {}", i), || Ok(self.bd[i]))?;
            //line 4
            let frc = cs.alloc(|| format!("frc {}", i), || Ok(self.frc[i]))?;
            let frc_ext = cs.alloc(|| format!("frc_ext {}", i), || Ok(self.frc_ext[i]))?;
            bin_gadget(
                cs,
                self.bin_vals[bin_val_iter].clone(),
                frc_ext,
                self.powers_of_two,
            )?;
            bin_val_iter += 1;
            let frc_ext2 = cs.alloc(|| format!("frc_ext2 {}", i), || Ok(self.frc_ext2[i]))?;
            bin_gadget(
                cs,
                self.bin_vals[bin_val_iter].clone(),
                frc_ext2,
                self.powers_of_two,
            )?;
            bin_val_iter += 1;
            //line 5
            let ei = cs.alloc(|| format!("ei {}", i), || Ok(self.ei[i]))?;
            gather_e = gather_e + ei;
            //line 6
            let n1n2 = cs.alloc(|| format!("n1n2 {}", i), || Ok(self.n1n2[i]))?;
            let n1n2ac = cs.alloc(|| format!("n1n2ac {}", i), || Ok(self.n1n2ac[i]))?;
            let vn = cs.alloc(|| format!("vn {}", i), || Ok(self.vn[i]))?;
            //line 7
            let bd2 = cs.alloc(|| format!("bd2 {}", i), || Ok(self.bd2[i]))?;
            let vd = cs.alloc(|| format!("vd {}", i), || Ok(self.vd[i]))?;
            //line 8
            let vi = cs.alloc(|| format!("vi {}", i), || Ok(self.vi[i]))?;
            gather_v = gather_v + vi;
            let vi_ext = cs.alloc(|| format!("vi_ext {}", i), || Ok(self.vi_ext[i]))?;
            bin_gadget(
                cs,
                self.bin_vals[bin_val_iter].clone(),
                vi_ext,
                self.powers_of_two,
            )?;
            bin_val_iter += 1;
            let vi_ext2 = cs.alloc(|| format!("vi_ext2 {}", i), || Ok(self.vi_ext2[i]))?;
            bin_gadget(
                cs,
                self.bin_vals[bin_val_iter].clone(),
                vi_ext2,
                self.powers_of_two,
            )?;
            bin_val_iter += 1;

            //Constraints
            cs.enforce(|| "line2", |lc| lc, |lc| lc, |lc| lc + di0 + di1 - ac);
            cs.enforce(|| "line3", |lc| lc, |lc| lc, |lc| lc + ni0 + ni1 - bd);
            cs.enforce(
                || "line4-1",
                |lc| lc + bd,
                |lc| lc + frc,
                |lc| lc - bd + (pow_2k_as_f, ac) + frc_ext,
            );
            cs.enforce(
                || "line4-2",
                |lc| lc + bd,
                |lc| lc + frc,
                |lc| lc + bd + (pow_2k_as_f, ac) - frc_ext2,
            );
            cs.enforce(
                || "line5",
                |lc| lc + frc,
                |lc| lc + ni0,
                |lc| lc + ei,
            );
            cs.enforce(
                || "line6-mul1",
                |lc| lc + ni0,
                |lc| lc + ni1,
                |lc| lc + n1n2,
            );
            cs.enforce(
                || "line6-mul2",
                |lc| lc + n1n2,
                |lc| lc + ac,
                |lc| lc + n1n2ac,
            );
            cs.enforce(
                || "line6-mul3",
                |lc| lc + n1n2ac,
                |lc| lc + bd - ac,
                |lc| lc + vn,
            );
            cs.enforce(
                || "line7-mul1",
                |lc| lc + bd,
                |lc| lc + bd,
                |lc| lc + bd2,
            );
            cs.enforce(
                || "line7-mul2",
                |lc| lc + bd2,
                |lc| lc + bd - CS::one(),
                |lc| lc + vd,
            );
            cs.enforce(
                || format!("line8 {}", i),
                |lc| lc + vi,
                |lc| lc + vd,
                |lc| lc - vd + (pow_2k_as_f, vn) + vi_ext,
            );
            cs.enforce(
                || format!("line8 {}", i),
                |lc| lc + vi,
                |lc| lc + vd,
                |lc| lc + vd + (pow_2k_as_f, vn) - vi_ext2,
            );
        }

        let d = cs.alloc(|| "d", || Ok(self.d))?;
        let e = cs.alloc(|| "e", || Ok(self.e))?;
        let v = cs.alloc(|| "v", || Ok(self.v))?;

        cs.enforce(|| "sum d", |lc| lc, |lc| lc, |lc| lc + d - gather_d);
        cs.enforce(|| "sum e", |lc| lc, |lc| lc, |lc| lc + e - gather_e);
        cs.enforce(|| "sum v", |lc| lc, |lc| lc, |lc| lc + v - gather_v);

        //Algorithm 3
        let dmi = cs.alloc(|| "dmi", || Ok(self.dmi))?;
        let chi0 = cs.alloc(|| "chi0", || Ok(self.chi0))?;
        let chi0_ext = cs.alloc(|| "chi0_ext", || Ok(self.chi0_ext))?;
        let chi0_ext2 = cs.alloc(|| "chi0_ext", || Ok(self.chi0_ext2))?;
        let chi = cs.alloc_input(|| "chi", || Ok(self.chi))?;
        let chi_ext = cs.alloc(|| "chi_ext", || Ok(self.chi_ext))?;
        let chi_ext2 = cs.alloc(|| "chi_ext", || Ok(self.chi_ext2))?;
        cs.enforce(|| "line 3: alg3", |lc| lc, |lc| lc, |lc| lc + (pow_2k_as_f, d) - e - dmi);
        cs.enforce(
            || "line4 : alg3",
            |lc| lc + chi0,
            |lc| lc + v,
            |lc| lc - v + (pow_2k_as_f, dmi) + chi0_ext,
        );
        bin_gadget(
            cs,
            self.bin_vals[bin_val_iter].clone(),
            chi0_ext,
            self.powers_of_two,
        )?;
        bin_val_iter += 1;
        cs.enforce(
            || "line4-2 : alg3",
            |lc| lc + chi0,
            |lc| lc + v,
            |lc| lc + v + (pow_2k_as_f, dmi) - chi0_ext2,
        );
        bin_gadget(
            cs,
            self.bin_vals[bin_val_iter].clone(),
            chi0_ext2,
            self.powers_of_two,
        )?;
        bin_val_iter += 1;
        cs.enforce(
            || "line5 : alg3",
            |lc| lc + chi0,
            |lc| lc + dmi,
            |lc| lc + (pow_2k_as_f, CS::one()) + (pow_2k_as_f, chi) - chi_ext,
        );
        bin_gadget(
            cs,
            self.bin_vals[bin_val_iter].clone(),
            chi_ext,
            self.powers_of_two,
        )?;
        bin_val_iter += 1;
        cs.enforce(
            || "line5-2: alg3",
            |lc| lc + chi0,
            |lc| lc + dmi,
            |lc| lc - (pow_2k_as_f, CS::one()) + (pow_2k_as_f, chi) + chi_ext2,
        );
        bin_gadget(
            cs,
            self.bin_vals[bin_val_iter].clone(),
            chi_ext2,
            self.powers_of_two,
        )?;
        Ok(())
    }
}

impl<'a, F: Field> Compare<'a, F> {
    pub(crate) fn new(
        n: usize,
        bids: Vec<u64>,
        bids_as_feild_elems: Vec<F>,
        powers_of_two: &'a Vec<F>,
        powers_of_two_as_u64: &'a Vec<u64>,
    ) -> Self {
        Self {
            n: n,
            bids: bids,
            bids_as_feild_elems: bids_as_feild_elems,
            diff_bin: vec![],
            diff_vec: vec![],
            res: vec![],
            res_val: vec![],
            a_res: vec![],
            b_res: vec![],
            powers_of_two: powers_of_two,
            powers_of_two_as_u64: powers_of_two_as_u64,
        }
    }

    pub(crate) fn solve(&mut self) {
        let mut max_bid_ind = 0;
        for i in 1..self.bids.len() {
            let res = self.bids[max_bid_ind];
            let mut diff = self.powers_of_two_as_u64[self.n] + res - self.bids[i];
            let diff_as_field_elem = self.powers_of_two[self.n]
                + self.bids_as_feild_elems[max_bid_ind]
                - self.bids_as_feild_elems[i];
            let mut diff_bits = vec![F::zero(); self.n + 1];
            let mut j = 0;
            while diff > 0 {
                let last_bit = diff % 2;
                diff = diff / 2u64;
                if last_bit == 1 {
                    diff_bits[j] = F::one();
                }
                j += 1;
            }
            self.diff_bin.push(diff_bits);
            self.diff_vec.push(diff_as_field_elem);
            if self.bids[max_bid_ind] >= self.bids[i] {
                self.res.push(F::one());
                self.res_val.push(self.bids_as_feild_elems[max_bid_ind]);
                self.a_res.push(self.bids_as_feild_elems[max_bid_ind]);
                self.b_res.push(F::zero());
            } else {
                self.res.push(F::zero());
                self.res_val.push(self.bids_as_feild_elems[i]);
                self.b_res.push(self.bids_as_feild_elems[i]);
                self.a_res.push(F::zero());
                max_bid_ind = i;
            }
        }
        let win_bid = self.bids.iter().max().unwrap();
        assert_eq!(
            self.bids.iter().position(|r| r == win_bid).unwrap(),
            self.bids_as_feild_elems
                .iter()
                .position(|r| r == self.res_val.last().unwrap())
                .unwrap()
        );
    }
}

impl<'a, ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Compare<'a, ConstraintF> {
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Allocate all the inputs
        let mut bid_vars = vec![];
        for i in 0..self.bids_as_feild_elems.len() {
            let bid_var =
                cs.alloc_input(|| format!("bid {}", i), || Ok(self.bids_as_feild_elems[i]))?;
            bid_vars.push(bid_var);
        }
        let final_res =
            cs.alloc_input(|| "final_res", || Ok(self.res_val[self.res_val.len() - 1]))?;

        // Allocate all the intermidiate diff results and diff binary reps
        let mut prev_best = bid_vars[0];
        for i in 0..self.diff_bin.len() {
            let curr_bid = bid_vars[i + 1];
            let diff = cs.alloc(|| format!("diff {}", i), || Ok(self.diff_vec[i]))?;
            let res = cs.alloc(|| format!("res {}", i), || Ok(self.res[i]))?;
            let res_val = cs.alloc(|| format!("res_val {}", i), || Ok(self.res_val[i]))?;
            let a_res = cs.alloc(|| format!("res_val {}", i), || Ok(self.a_res[i]))?;
            let b_res = cs.alloc(|| format!("res_val {}", i), || Ok(self.b_res[i]))?;
            let mut bin_vars = vec![];
            for j in 0..self.diff_bin[i].len() {
                let bin_var = cs.alloc(
                    || format!("Binary Constraint {} {}", i, j),
                    || Ok(self.diff_bin[i][j]),
                )?;
                bin_vars.push(bin_var);
                cs.enforce(
                    || format!("Variable {}: 1 or 0", i),
                    |lc| lc + bin_var,
                    |lc| lc + CS::one() - bin_var,
                    |lc| lc,
                );
            }
            //Gathering constraint
            let mut gather_lc = LinearCombination::<ConstraintF>::zero();
            for k in 0..bin_vars.len() {
                gather_lc = gather_lc + (self.powers_of_two[k], bin_vars[k]);
            }
            cs.enforce(
                || "Binary summation",
                |lc| lc,
                |lc| lc,
                |lc| lc + gather_lc - diff,
            );
            // First constraint: 2**n + a - b = diff
            cs.enforce(
                || format!("constraint 2^n - a + b = diff"),
                |lc| lc,
                |lc| lc,
                |lc| lc + (self.powers_of_two[self.n], CS::one()) + prev_best - curr_bid - diff,
            );
            // Comparison output
            cs.enforce(
                || "Result",
                |lc| lc,
                |lc| lc,
                |lc| lc + bin_vars[self.n] - res,
            );
            // Value constraints
            cs.enforce(
                || "a*res",
                |lc| lc + prev_best,
                |lc| lc + res,
                |lc| lc + a_res,
            );
            cs.enforce(
                || "b*(1-res)",
                |lc| lc + curr_bid,
                |lc| lc + CS::one() - res,
                |lc| lc + b_res,
            );
            cs.enforce(
                || "final_res",
                |lc| lc,
                |lc| lc,
                |lc| lc + b_res + a_res - res_val,
            );
            if i == self.diff_bin.len() - 1 {
                cs.enforce(|| "Final", |lc| lc, |lc| lc, |lc| lc + res_val - final_res);
            }
            //update iterables
            prev_best = res_val;
        }
        Ok(())
    }
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit<ConstraintF> {
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.alloc(
            || "c",
            || {
                let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                a.mul_assign(&b);
                Ok(a)
            },
        )?;
        let d = cs.alloc_input(|| "d", || self.d.ok_or(SynthesisError::AssignmentMissing))?;
        let e = cs.alloc_input(|| "e", || self.e.ok_or(SynthesisError::AssignmentMissing))?;
        for i in 0..(self.num_variables - 6 - (self.num_input_variables - 4)) {
            let _ = cs.alloc(
                || format!("var {}", i),
                || self.a.ok_or(SynthesisError::AssignmentMissing),
            )?;
        }
        let v = self.stmt_inputs.clone();
        for i in 0..self.num_input_variables - 4 {
            let _ = cs.alloc_input(
                || format!("input {}", i),
                || match v.clone() {
                    Some(v) => Ok(v[i]),
                    None => Err(SynthesisError::AssignmentMissing),
                },
            )?;
        }
        let f = cs.alloc_input(|| "f", || self.f.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce(
            || format!("constraint {}", self.num_constraints - 1),
            |lc| lc + d,
            |lc| lc + e,
            |lc| lc + f,
        );

        for i in 0..self.num_constraints - 1 {
            cs.enforce(
                || format!("constraint {}", i),
                |lc| lc + a,
                |lc| lc + b,
                |lc| lc + c,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod marlin {
    use super::*;
    use crate::AuditableMarlin;

    use crate::{COMM_BANDWIDTH, COMM_LATENCY};
    use algebra::UniformRand;
    use algebra::{bls12_381::Fr, Bls12_381};
    use blake2::Blake2s;
    use core::ops::MulAssign;

    type MarlinInst = AuditableMarlin<Bls12_381, Blake2s>;
    use crate::auction::client::Client;
    use crate::auction::server::MPCserver;
    use crate::mpc::interpolate::interpolate_shares;
    use crate::mpc::interpolate::pec_batch_interpolate_shares_exponent;
    use crate::pec_round_comm_size;
    use crate::ped_commitments::pec_polycommit::PECPolycommit;
    use crate::ped_commitments::pederson::PedersonCommitment;
    use crate::MPCConfig;
    use crate::Preprocess;
    use core::ops::Mul;
    use std::thread::sleep;
    use std::time::Duration;

    fn distribute_shared_circuit<'a>(circ: &Compare<'a, Fr>, servers: &mut Vec<MPCserver>) -> Vec<Compare<'a, Fr>>{
        let mut ret = vec![];
        for j in 0..servers.len(){
            let mut solved_circ = circ.clone();
            for i in 0..circ.bids_as_feild_elems.len(){
                solved_circ.bids_as_feild_elems[i] += &servers[j].get_new_zero_share();
            }
            for i in 0..circ.diff_bin.len(){
                for k in 0..circ.diff_bin[i].len(){
                    solved_circ.diff_bin[i][k] += &servers[j].get_new_zero_share();
                }
                solved_circ.diff_vec[i] +=  &servers[j].get_new_zero_share();
                solved_circ.res[i] +=  &servers[j].get_new_zero_share();
                solved_circ.res_val[i] +=  &servers[j].get_new_zero_share();
                solved_circ.a_res[i] +=  &servers[j].get_new_zero_share();
                solved_circ.b_res[i] +=  &servers[j].get_new_zero_share();
            }
            ret.push(solved_circ);
        }
        ret
    }
    
    fn distribute_shared_logrank<'a>(
        circ: &LogRank<'a, Fr>,
        servers: &mut Vec<MPCserver>,
    ) -> Vec<LogRank<'a, Fr>> {
        let mut ret = vec![];
        for j in 0..servers.len() {
            let num_samples = circ.di[0].len();
            let mut solved_circ = circ.clone();

            for i in 0..num_samples {
                for k in 0..2 {
                    solved_circ.di[k][i] += &servers[j].get_new_zero_share();
                    solved_circ.ni[k][i] += &servers[j].get_new_zero_share();
                }
                solved_circ.ac[i] += &servers[j].get_new_zero_share();
                solved_circ.bd[i] += &servers[j].get_new_zero_share();
                solved_circ.frc[i] += &servers[j].get_new_zero_share();
                solved_circ.frc_ext[i] += &servers[j].get_new_zero_share();
                solved_circ.ei[i] += &servers[j].get_new_zero_share();
                solved_circ.vn[i] += &servers[j].get_new_zero_share();
                solved_circ.n1n2[i] += &servers[j].get_new_zero_share();
                solved_circ.n1n2ac[i] += &servers[j].get_new_zero_share();
                solved_circ.bd2[i] += &servers[j].get_new_zero_share();
                solved_circ.vi[i] += &servers[j].get_new_zero_share();
                solved_circ.vi_ext[i] += &servers[j].get_new_zero_share();
            }
            solved_circ.e += &servers[j].get_new_zero_share();
            solved_circ.v += &servers[j].get_new_zero_share();
            solved_circ.d += &servers[j].get_new_zero_share();
            solved_circ.dmi += &servers[j].get_new_zero_share();
            solved_circ.chi0 += &servers[j].get_new_zero_share();
            solved_circ.chi0_ext += &servers[j].get_new_zero_share();
            solved_circ.chi += &servers[j].get_new_zero_share();
            solved_circ.chi_ext += &servers[j].get_new_zero_share();

            for i in 0..solved_circ.bin_vals.len() {
                for k in 0..solved_circ.bin_vals[i].len() {
                    solved_circ.bin_vals[i][k] += &servers[j].get_new_zero_share();
                }
            }
            ret.push(solved_circ);
        }
        ret
    }

    fn test_logrank(
        num_constraints: usize,
        num_variables: usize,
        num_servers: usize,
        stmt_len: usize,
        num_bits: usize,
    ) {
        let rng = &mut algebra::test_rng();

        // ---------------------------------------------
        // Step 1: One time universal setups
        let universal_srs =
            MarlinInst::universal_setup(num_constraints, num_variables, num_constraints, rng)
                .unwrap();
        let mpc_cfg = MPCConfig {
            num_parties: num_servers,
            num_corruptions: num_servers / 3,
        };

        let comm_len = stmt_len;
        let stmt_len = nearest_pow_of_two(stmt_len * 4 + 2);
        let num_clients = stmt_len - 2;

        println!("Step 1a: Universal SRS setup complete!");

        let preproc = Preprocess::<Fr>::new(mpc_cfg, stmt_len, rng).unwrap();
        println!("Step 1b: MPC Preprocessing Complete");

        let ped_ck = PedersonCommitment::<Bls12_381>::setup(rng);
        println!("Step 1c: Pederson Commitment setup completed");

        //-------------------------------------
        //Generate random bids for clients
        let mut bids: Vec<u64> = vec![];
        let mut bids_as_f: Vec<Fr> = vec![];
        for _ in 0..num_clients {
            let bid: u64 = rng.gen_range(1, 2u64.pow(num_bits as u32));
            bids.push(bid);
            bids_as_f.push(Fr::from_repr(BigInteger256::from(bid)));
        }
        //--------------------------------------
        // ------------------------------------------
        let _zero = Fr::from_repr(BigInteger256::from(0));
        let _one = Fr::from_repr(BigInteger256::from(1));
        let _two = Fr::from_repr(BigInteger256::from(2));
        let _five = Fr::from_repr(BigInteger256::from(5));
        let _ten = Fr::from_repr(BigInteger256::from(10));
        // -----------------------------------------

        let mut powers_of_two = vec![];
        let mut powers_of_two_as_u64 = vec![];
        let mut val = _one;
        let mut v = 1u64;
        for _ in 0..63 {
            powers_of_two.push(val);
            powers_of_two_as_u64.push(v);
            val = val * &_two;
            v = v * 2;
        }

        let mut comp_circ = Compare::new(
            num_bits,
            bids,
            bids_as_f.clone(),
            &powers_of_two,
            &powers_of_two_as_u64,
        );
        comp_circ.solve();

        let mut logrank = LogRank::new(
            20,
            vec![vec![_five; comm_len], vec![_two; comm_len]],
            vec![vec![_ten; comm_len], vec![_five; comm_len]],
            vec![vec![5; comm_len], vec![2; comm_len]],
            vec![vec![10; comm_len], vec![5; comm_len]],
            &powers_of_two,
            &powers_of_two_as_u64,
        );
        logrank.solve();

        //TODO: Call trim instead of reusing
        // let (index_pk, index_vk) = MarlinInst::index(&universal_srs, comp_circ.clone()).unwrap();
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, logrank.clone()).unwrap();
        println!("Step 1d: Called indexer for a specific circuit");

        let pec_ck = PECPolycommit::setup(&index_pk.committer_key, stmt_len);

        // ---------------------------------------------
        // Initalize servers, indexer etc. This can be done
        // multiple times in reactive MPC
        let mut clients = vec![];
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        for id in 0..num_clients {
            let x = bids_as_f[id];
            let client = Client::new(id, x, ped_ck);
            clients.push(client);
        }
        println!("Step 2a: Created MPC clients");

        let mut servers = vec![];
        for id in 0..mpc_cfg.num_parties {
            let server = MPCserver::new(id, &preproc, ped_ck);
            servers.push(server);
        }
        println!("Step 2b: Servers initialized");

        // ---------------------------------------------
        // Step 3 of the protocol: Process client inputs
        let mut cli_inp_comms = vec![];
        for j in 0..num_clients {
            // Step 3a: Commit to each client inputs
            cli_inp_comms.push(clients[j].pec_commit_input::<_, Blake2s>(&pec_ck, rng));
            // Step 3b: Get the random shares for a particular client
            let mut client_rand_shares = vec![];
            let mut rand_idx = vec![0; 3];
            for k in 0..3 {
                let mut single_rand_shares = vec![];
                for i in 0..mpc_cfg.num_parties {
                    // Process 3 random sharse. One for input and two for polyshares
                    let (rand_share, rand_index) = servers[i].get_rand_share();
                    rand_idx[k] = rand_index;
                    single_rand_shares.push(rand_share);
                }
                client_rand_shares.push(single_rand_shares);
            }
            // Step 3c: Calculate the input mask and get the input commitment
            let masked_input = clients[j]
                .recieve_random_shares(client_rand_shares, &preproc, mpc_cfg)
                .unwrap();

            // Step 3d: Process masked input, save the input shares
            // and evaluate the circuits
            for i in 0..mpc_cfg.num_parties {
                servers[i].process_masked_input(masked_input.clone(), rand_idx.clone());
            }

            // Test that the inputs are correctly processed.
            let mut inp_shares = vec![];
            let mut inp_shares2 = vec![];
            let mut rand_shares = vec![];
            for i in 0..mpc_cfg.num_parties {
                inp_shares.push(servers[i].client_inputs[j]);
                inp_shares2.push(servers[i].client_rand_inputs[2 * j]);
                rand_shares.push(servers[i].random_shares[3 * j]);
            }
            let recon_inp = interpolate_shares(&preproc, inp_shares, mpc_cfg).unwrap();
            let recon_hid = interpolate_shares(&preproc, inp_shares2, mpc_cfg).unwrap();
            let recon_rand = interpolate_shares(&preproc, rand_shares, mpc_cfg).unwrap();
            assert_eq!(clients[j].input[0], recon_inp);
            assert_eq!(clients[j].input[1], recon_hid);
            assert_eq!(clients[j].random_v_from_servers[0], recon_rand);
            //Test cell end
        }
        // // Step 4a: Calculate the circuit on each server with the inputs.
        // //Evalute the circuit and feed in the witness values.
        let mut d_shares = vec![];
        let mut e_shares = vec![];

        for i in 0..mpc_cfg.num_parties {
            let ((a, b, _ab), _ind) = servers[i].get_new_triple();
            let d_share = servers[i].client_inputs[0] - &a;
            let e_share = servers[i].client_inputs[1] - &b;
            d_shares.push(d_share);
            e_shares.push(e_share);
        }

        // ----------------------------------------------------
        // Test cell: Beaver triple
        let mut triple_a = vec![];
        let mut triple_b = vec![];
        let mut triple_ab = vec![];
        for i in 0..mpc_cfg.num_parties {
            triple_a.push(servers[i].triple_shares[0].0);
            triple_b.push(servers[i].triple_shares[0].1);
            triple_ab.push(servers[i].triple_shares[0].2);
        }
        let t_a = interpolate_shares(&preproc, triple_a, mpc_cfg).unwrap();
        let t_b = interpolate_shares(&preproc, triple_b, mpc_cfg).unwrap();
        let t_ab = interpolate_shares(&preproc, triple_ab, mpc_cfg).unwrap();
        assert_eq!(t_a.mul(&t_b), t_ab);
        //----------------------------------------------------------

        let solved_circuits = distribute_shared_logrank(&logrank, &mut servers);
        // let mut solved_circuits = vec![];
        for i in 0..mpc_cfg.num_parties {
            // let comp_circ_solved = comp_circ.clone();
            // let res = solved_circuits[i].res_val.last().unwrap();
            // output_shares.push(*res);
            // solved_circuits.push(logrank.clone());
            servers[i].set_server_output(vec![_five]);
            // solved_circuits.push(comp_circ_solved);
        }
        // Get the partial commitments
        let mut server_opt_comms = vec![];
        let mut server_inp_comms = vec![];
        for i in 0..mpc_cfg.num_parties {
            let output_comm_time = start_timer!(|| "Computing Partial Commitments to output");
            let server_opt_partial_comm = servers[i].get_server_output_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            let server_inp_partial_comm = servers[i].get_server_input_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            server_opt_comms.push(server_opt_partial_comm);
            server_inp_comms.push(server_inp_partial_comm);
            end_timer!(output_comm_time);
        }
        // //--------------------------------------------------------
        // //test cell: Test that the beaver multiplication works.
        // let out = interpolate_shares(&preproc, output_shares, mpc_cfg).unwrap();
        // dbg!(&out.to_string());
        // let mut server_output_shares = vec![];
        // for i in 0..mpc_cfg.num_parties {
        //     server_output_shares.push(servers[i].server_outputs[0]);
        // }
        // let mul_res = interpolate_shares(&preproc, server_output_shares, mpc_cfg).unwrap();
        // assert_eq!(mul_res, clients[0].input[0].mul(&clients[1].input[0]));
        // //-------------------------------------------------------

        // Step 4b: Send partial comms to all servers. Commit to the outputs of the circuit
        // Ideally this commitment should be a threshold signature for now. But we are
        // ignoring this aspect for now.
        // Collect all random_shares for marlin prover step
        // Collect all input shares and check that they are consistent
        let mut rand_assignments = vec![];
        let init_round_bytes_sent =
            pec_round_comm_size(&server_inp_comms[0]) + pec_round_comm_size(&server_opt_comms[0]);
        let init_comm_time = start_timer!(|| "Initial Commitment and Output Check time");
        let total_delay = 10.0_f64.powi(6i32) * COMM_LATENCY
            + ((init_round_bytes_sent * 8) as f64) / (COMM_BANDWIDTH * 10.0_f64.powi(6i32))
                * 10.0_f64.powi(9i32);
        let sec_delay = (total_delay / (10u64.pow(9u32) as f64)) as u64;
        let nano_delay = ((total_delay as u64) - sec_delay * 10u64.pow(9u32)) as u32;
        sleep(Duration::new(sec_delay, nano_delay));

        let cli_inp_comm_from_server =
            pec_batch_interpolate_shares_exponent(&preproc, &server_inp_comms, mpc_cfg).unwrap();
        // dbg!(&cli_inp_comm_from_server[0]);
        for comm_iter in 0..cli_inp_comm_from_server.len() {
            assert_eq!(
                cli_inp_comm_from_server[comm_iter].commitment().comm,
                cli_inp_comms[comm_iter].commitment().comm
            );
        }
        let server_output_com = servers[0]
            .combine_pec_output_comm(&preproc, &server_opt_comms, mpc_cfg)
            .unwrap();
        end_timer!(init_comm_time);

        for i in 0..mpc_cfg.num_parties {
            rand_assignments.push(servers[i].client_rand_inputs.clone());
        }
        cli_inp_comms.extend(server_output_com);
        let statement_comms = cli_inp_comms;

        //Create the final statement commitment
        let mut final_stmt_comms = vec![PECPolycommit::commit_to_one(&pec_ck)];
        final_stmt_comms.extend(statement_comms);

        let final_stmt_comm =
            PECPolycommit::pec_interpolate("x_poly".to_owned(), final_stmt_comms.clone());
        // Step 5: Marlin proof
        // let _a = Fr::from_repr(BigInteger256::from(1));
        let mut c = a;
        c.mul_assign(&b);
        let proof = MarlinInst::prove(
            &index_pk,
            *final_stmt_comm.commitment(),
            &rand_assignments,
            &preproc,
            mpc_cfg,
            solved_circuits,
            rng,
        )
        .unwrap();
        println!("Called prover");

        let auditor_avg_time = start_timer!(|| "Auditer average time");
        for _ in 0..10 {
            assert!(MarlinInst::audit(&index_vk, final_stmt_comms.clone(), &proof, rng).unwrap());
            println!("Called auditor");
        }
        end_timer!(auditor_avg_time);
    }

    fn test_auction(
        num_constraints: usize,
        num_variables: usize,
        num_servers: usize,
        stmt_len: usize,
        num_bits: usize,
    ) {
        let rng = &mut algebra::test_rng();

        // ---------------------------------------------
        // Step 1: One time universal setups
        let universal_srs =
            MarlinInst::universal_setup(num_constraints, num_variables, num_constraints, rng)
                .unwrap();
        let mpc_cfg = MPCConfig {
            num_parties: num_servers,
            num_corruptions: num_servers / 3,
        };

        let num_clients = stmt_len - 2;

        println!("Step 1a: Universal SRS setup complete!");

        let preproc = Preprocess::<Fr>::new(mpc_cfg, stmt_len, rng).unwrap();
        println!("Step 1b: MPC Preprocessing Complete");

        let ped_ck = PedersonCommitment::<Bls12_381>::setup(rng);
        println!("Step 1c: Pederson Commitment setup completed");

        //-------------------------------------
        //Generate random bids for clients
        let mut bids :Vec<u64> = vec![];
        let mut bids_as_f: Vec<Fr> = vec![];
        for _ in 0..num_clients{
            let bid: u64 = rng.gen_range(1, 2u64.pow(num_bits as u32));
            bids.push(bid);
            bids_as_f.push(Fr::from_repr(BigInteger256::from(bid)));
        }
        //--------------------------------------
        // ------------------------------------------
        let _zero = Fr::from_repr(BigInteger256::from(0));
        let _one = Fr::from_repr(BigInteger256::from(1));
        let _two = Fr::from_repr(BigInteger256::from(2));
        let _five = Fr::from_repr(BigInteger256::from(5));
        let _ten = Fr::from_repr(BigInteger256::from(10));
        // -----------------------------------------

        let mut powers_of_two = vec![];
        let mut powers_of_two_as_u64 = vec![];
        let mut val = _one;
        let mut v = 1u64;
        for _ in 0..63 {
            powers_of_two.push(val);
            powers_of_two_as_u64.push(v);
            val = val * &_two;
            v = v * 2;
        }

        let mut comp_circ = Compare::new(
            num_bits,
            bids,
            bids_as_f.clone(),
            &powers_of_two,
            &powers_of_two_as_u64,
        );
        comp_circ.solve();

        //TODO: Call trim instead of reusing
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, comp_circ.clone()).unwrap();
        println!("Step 1d: Called indexer for a specific circuit");

        let pec_ck = PECPolycommit::setup(&index_pk.committer_key, stmt_len);

        // ---------------------------------------------
        // Initalize servers, indexer etc. This can be done
        // multiple times in reactive MPC
        let mut clients = vec![];
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        for id in 0..num_clients {
            let x = bids_as_f[id];
            let client = Client::new(id, x, ped_ck);
            clients.push(client);
        }
        println!("Step 2a: Created MPC clients");

        let mut servers = vec![];
        for id in 0..mpc_cfg.num_parties {
            let server = MPCserver::new(id, &preproc, ped_ck);
            servers.push(server);
        }
        println!("Step 2b: Servers initialized");

        // ---------------------------------------------
        // Step 3 of the protocol: Process client inputs
        let mut cli_inp_comms = vec![];
        for j in 0..num_clients {
            // Step 3a: Commit to each client inputs
            cli_inp_comms.push(clients[j].pec_commit_input::<_, Blake2s>(&pec_ck, rng));
            // Step 3b: Get the random shares for a particular client
            let mut client_rand_shares = vec![];
            let mut rand_idx = vec![0; 3];
            for k in 0..3 {
                let mut single_rand_shares = vec![];
                for i in 0..mpc_cfg.num_parties {
                    // Process 3 random sharse. One for input and two for polyshares
                    let (rand_share, rand_index) = servers[i].get_rand_share();
                    rand_idx[k] = rand_index;
                    single_rand_shares.push(rand_share);
                }
                client_rand_shares.push(single_rand_shares);
            }
            // Step 3c: Calculate the input mask and get the input commitment
            let masked_input = clients[j]
                .recieve_random_shares(client_rand_shares, &preproc, mpc_cfg)
                .unwrap();

            // Step 3d: Process masked input, save the input shares
            // and evaluate the circuits
            for i in 0..mpc_cfg.num_parties {
                servers[i].process_masked_input(masked_input.clone(), rand_idx.clone());
            }

            // Test that the inputs are correctly processed.
            let mut inp_shares = vec![];
            let mut inp_shares2 = vec![];
            let mut rand_shares = vec![];
            for i in 0..mpc_cfg.num_parties {
                inp_shares.push(servers[i].client_inputs[j]);
                inp_shares2.push(servers[i].client_rand_inputs[2 * j]);
                rand_shares.push(servers[i].random_shares[3 * j]);
            }
            let recon_inp = interpolate_shares(&preproc, inp_shares, mpc_cfg).unwrap();
            let recon_hid = interpolate_shares(&preproc, inp_shares2, mpc_cfg).unwrap();
            let recon_rand = interpolate_shares(&preproc, rand_shares, mpc_cfg).unwrap();
            assert_eq!(clients[j].input[0], recon_inp);
            assert_eq!(clients[j].input[1], recon_hid);
            assert_eq!(clients[j].random_v_from_servers[0], recon_rand);
            //Test cell end
        }
        // // Step 4a: Calculate the circuit on each server with the inputs.
        // //Evalute the circuit and feed in the witness values.
        let mut d_shares = vec![];
        let mut e_shares = vec![];

        for i in 0..mpc_cfg.num_parties {
            let ((a, b, _ab), _ind) = servers[i].get_new_triple();
            let d_share = servers[i].client_inputs[0] - &a;
            let e_share = servers[i].client_inputs[1] - &b;
            d_shares.push(d_share);
            e_shares.push(e_share);
        }

        // ----------------------------------------------------
        // Test cell: Beaver triple
        let mut triple_a = vec![];
        let mut triple_b = vec![];
        let mut triple_ab = vec![];
        for i in 0..mpc_cfg.num_parties {
            triple_a.push(servers[i].triple_shares[0].0);
            triple_b.push(servers[i].triple_shares[0].1);
            triple_ab.push(servers[i].triple_shares[0].2);
        }
        let t_a = interpolate_shares(&preproc, triple_a, mpc_cfg).unwrap();
        let t_b = interpolate_shares(&preproc, triple_b, mpc_cfg).unwrap();
        let t_ab = interpolate_shares(&preproc, triple_ab, mpc_cfg).unwrap();
        assert_eq!(t_a.mul(&t_b), t_ab);
        //----------------------------------------------------------

        let solved_circuits = distribute_shared_circuit(&comp_circ, &mut servers);
        let mut output_shares = vec![];
        for i in 0..mpc_cfg.num_parties {
            // let comp_circ_solved = comp_circ.clone();
            let res = solved_circuits[i].res_val.last().unwrap();
            output_shares.push(*res);
            servers[i].set_server_output(vec![*res]);
            // solved_circuits.push(comp_circ_solved);
        }
        // Get the partial commitments
        let mut server_opt_comms = vec![];
        let mut server_inp_comms = vec![];
        for i in 0..mpc_cfg.num_parties {
            let output_comm_time = start_timer!(|| "Computing Partial Commitments to output");
            let server_opt_partial_comm = servers[i].get_server_output_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            let server_inp_partial_comm = servers[i].get_server_input_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            server_opt_comms.push(server_opt_partial_comm);
            server_inp_comms.push(server_inp_partial_comm);
            end_timer!(output_comm_time);
        }
        // //--------------------------------------------------------
        // //test cell: Test that the beaver multiplication works.
        // let out = interpolate_shares(&preproc, output_shares, mpc_cfg).unwrap();
        // dbg!(&out.to_string());
        // let mut server_output_shares = vec![];
        // for i in 0..mpc_cfg.num_parties {
        //     server_output_shares.push(servers[i].server_outputs[0]);
        // }
        // let mul_res = interpolate_shares(&preproc, server_output_shares, mpc_cfg).unwrap();
        // assert_eq!(mul_res, clients[0].input[0].mul(&clients[1].input[0]));
        // //-------------------------------------------------------

        // Step 4b: Send partial comms to all servers. Commit to the outputs of the circuit
        // Ideally this commitment should be a threshold signature for now. But we are
        // ignoring this aspect for now.
        // Collect all random_shares for marlin prover step
        // Collect all input shares and check that they are consistent
        let mut rand_assignments = vec![];
        let init_round_bytes_sent =
            pec_round_comm_size(&server_inp_comms[0]) + pec_round_comm_size(&server_opt_comms[0]);
        let init_comm_time = start_timer!(|| "Initial Commitment and Output Check time");
        let total_delay = 10.0_f64.powi(6i32) * COMM_LATENCY
            + ((init_round_bytes_sent * 8) as f64) / (COMM_BANDWIDTH * 10.0_f64.powi(6i32))
                * 10.0_f64.powi(9i32);
        let sec_delay = (total_delay / (10u64.pow(9u32) as f64)) as u64;
        let nano_delay = ((total_delay as u64) - sec_delay * 10u64.pow(9u32)) as u32;
        sleep(Duration::new(sec_delay, nano_delay));

        let cli_inp_comm_from_server =
            pec_batch_interpolate_shares_exponent(&preproc, &server_inp_comms, mpc_cfg).unwrap();
        // dbg!(&cli_inp_comm_from_server[0]);
        for comm_iter in 0..cli_inp_comm_from_server.len() {
            assert_eq!(
                cli_inp_comm_from_server[comm_iter].commitment().comm,
                cli_inp_comms[comm_iter].commitment().comm
            );
        }
        let server_output_com = servers[0]
            .combine_pec_output_comm(&preproc, &server_opt_comms, mpc_cfg)
            .unwrap();
        end_timer!(init_comm_time);

        for i in 0..mpc_cfg.num_parties {
            rand_assignments.push(servers[i].client_rand_inputs.clone());
        }
        cli_inp_comms.extend(server_output_com);
        let statement_comms = cli_inp_comms;

        //Create the final statement commitment
        let mut final_stmt_comms = vec![PECPolycommit::commit_to_one(&pec_ck)];
        final_stmt_comms.extend(statement_comms);

        let final_stmt_comm =
            PECPolycommit::pec_interpolate("x_poly".to_owned(), final_stmt_comms.clone());
        // Step 5: Marlin proof
        // let _a = Fr::from_repr(BigInteger256::from(1));
        let mut c = a;
        c.mul_assign(&b);
        let proof = MarlinInst::prove(
            &index_pk,
            *final_stmt_comm.commitment(),
            &rand_assignments,
            &preproc,
            mpc_cfg,
            solved_circuits,
            rng,
        )
        .unwrap();
        println!("Called prover");

        let auditor_avg_time = start_timer!(|| "Auditer average time");
        for _ in 0..10 {
            assert!(MarlinInst::audit(&index_vk, final_stmt_comms.clone(), &proof, rng).unwrap());
            println!("Called auditor");
        }
        end_timer!(auditor_avg_time);
    }

    fn test_auditable_mpc(
        num_constraints: usize,
        num_variables: usize,
        num_servers: usize,
        stmt_len: usize,
    ) {
        let rng = &mut algebra::test_rng();
        let num_input_variables = stmt_len;

        // ---------------------------------------------
        // Step 1: One time universal setups
        let universal_srs =
            MarlinInst::universal_setup(num_constraints, num_variables, num_constraints, rng)
                .unwrap();
        let mpc_cfg = MPCConfig {
            num_parties: num_servers,
            num_corruptions: num_servers / 3,
        };

        let num_clients = stmt_len - 2;

        println!("Step 1a: Universal SRS setup complete!");

        let preproc = Preprocess::<Fr>::new(mpc_cfg, stmt_len, rng).unwrap();
        println!("Step 1b: MPC Preprocessing Complete");

        let ped_ck = PedersonCommitment::<Bls12_381>::setup(rng);
        println!("Step 1c: Pederson Commitment setup completed");

        let ind_circ = Circuit {
            a: None,
            b: None,
            d: None,
            e: None,
            f: None,
            stmt_inputs: None,
            num_constraints,
            num_variables,
            num_input_variables,
        };

        //TODO: Call trim instead of reusing
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, ind_circ.clone()).unwrap();
        println!("Step 1d: Called indexer for a specific circuit");

        let pec_ck = PECPolycommit::setup(&index_pk.committer_key, stmt_len);

        // ---------------------------------------------
        // Initalize servers, indexer etc. This can be done
        // multiple times in reactive MPC

        // ------------------------------------------
        let _two = Fr::from_repr(BigInteger256::from(2));
        let _five = Fr::from_repr(BigInteger256::from(5));
        let _ten = Fr::from_repr(BigInteger256::from(10));
        // -----------------------------------------

        let mut clients = vec![];
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        for id in 0..num_clients {
            let x = Fr::rand(rng);
            let client = Client::new(id, x, ped_ck);
            clients.push(client);
        }
        println!("Step 2a: Created MPC clients");

        let mut servers = vec![];
        for id in 0..mpc_cfg.num_parties {
            let server = MPCserver::new(id, &preproc, ped_ck);
            servers.push(server);
        }
        println!("Step 2b: Servers initialized");

        // ---------------------------------------------
        // Step 3 of the protocol: Process client inputs
        let mut cli_inp_comms = vec![];
        for j in 0..num_clients {
            // Step 3a: Commit to each client inputs
            cli_inp_comms.push(clients[j].pec_commit_input::<_, Blake2s>(&pec_ck, rng));
            // Step 3b: Get the random shares for a particular client
            let mut client_rand_shares = vec![];
            let mut rand_idx = vec![0; 3];
            for k in 0..3 {
                let mut single_rand_shares = vec![];
                for i in 0..mpc_cfg.num_parties {
                    // Process 3 random sharse. One for input and two for polyshares
                    let (rand_share, rand_index) = servers[i].get_rand_share();
                    rand_idx[k] = rand_index;
                    single_rand_shares.push(rand_share);
                }
                client_rand_shares.push(single_rand_shares);
            }
            // Step 3c: Calculate the input mask and get the input commitment
            let masked_input = clients[j]
                .recieve_random_shares(client_rand_shares, &preproc, mpc_cfg)
                .unwrap();

            // Step 3d: Process masked input, save the input shares
            // and evaluate the circuits
            for i in 0..mpc_cfg.num_parties {
                servers[i].process_masked_input(masked_input.clone(), rand_idx.clone());
            }

            // Test that the inputs are correctly processed.
            let mut inp_shares = vec![];
            let mut inp_shares2 = vec![];
            let mut rand_shares = vec![];
            for i in 0..mpc_cfg.num_parties {
                inp_shares.push(servers[i].client_inputs[j]);
                inp_shares2.push(servers[i].client_rand_inputs[2 * j]);
                rand_shares.push(servers[i].random_shares[3 * j]);
            }
            let recon_inp = interpolate_shares(&preproc, inp_shares, mpc_cfg).unwrap();
            let recon_hid = interpolate_shares(&preproc, inp_shares2, mpc_cfg).unwrap();
            let recon_rand = interpolate_shares(&preproc, rand_shares, mpc_cfg).unwrap();
            assert_eq!(clients[j].input[0], recon_inp);
            assert_eq!(clients[j].input[1], recon_hid);
            assert_eq!(clients[j].random_v_from_servers[0], recon_rand);
            //Test cell end
        }
        // // Step 4a: Calculate the circuit on each server with the inputs.
        // //Evalute the circuit and feed in the witness values.
        let mut d_shares = vec![];
        let mut e_shares = vec![];
        let mut triple_ind: usize = 0;

        let mut solved_circuits = vec![];
        for i in 0..mpc_cfg.num_parties {
            let ((a, b, _ab), ind) = servers[i].get_new_triple();
            let d_share = servers[i].client_inputs[0] - &a;
            let e_share = servers[i].client_inputs[1] - &b;
            d_shares.push(d_share);
            e_shares.push(e_share);
            triple_ind = ind;
        }

        // ----------------------------------------------------
        // Test cell: Beaver triple
        let mut triple_a = vec![];
        let mut triple_b = vec![];
        let mut triple_ab = vec![];
        for i in 0..mpc_cfg.num_parties {
            triple_a.push(servers[i].triple_shares[0].0);
            triple_b.push(servers[i].triple_shares[0].1);
            triple_ab.push(servers[i].triple_shares[0].2);
        }
        let t_a = interpolate_shares(&preproc, triple_a, mpc_cfg).unwrap();
        let t_b = interpolate_shares(&preproc, triple_b, mpc_cfg).unwrap();
        let t_ab = interpolate_shares(&preproc, triple_ab, mpc_cfg).unwrap();
        assert_eq!(t_a.mul(&t_b), t_ab);
        //----------------------------------------------------------

        for i in 0..mpc_cfg.num_parties {
            let mul_share = servers[i]
                .beaver_mult(
                    &preproc,
                    mpc_cfg,
                    servers[i].client_inputs[0],
                    servers[i].client_inputs[1],
                    triple_ind,
                    d_shares.clone(),
                    e_shares.clone(),
                )
                .unwrap();
            let other_stmt_inputs = servers[i].client_inputs[2..].to_vec();
            let circ = Circuit {
                a: Some(a),
                b: Some(b),
                // d: Some(_two),
                d: Some(servers[i].client_inputs[0]),
                // e: Some(_five),
                e: Some(servers[i].client_inputs[1]),
                // f: Some(_ten),
                f: Some(mul_share),
                stmt_inputs: Some(other_stmt_inputs),
                num_constraints,
                num_variables,
                num_input_variables,
            };
            servers[i].set_server_output(vec![mul_share]);
            solved_circuits.push(circ);
        }
        // Get the partial commitments
        let mut server_opt_comms = vec![];
        let mut server_inp_comms = vec![];
        for i in 0..mpc_cfg.num_parties {
            let output_comm_time = start_timer!(|| "Computing Partial Commitments to output");
            let server_opt_partial_comm = servers[i].get_server_output_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            let server_inp_partial_comm = servers[i].get_server_input_pec_comm_share::<_, Blake2s>(&pec_ck, rng);
            server_opt_comms.push(server_opt_partial_comm);
            server_inp_comms.push(server_inp_partial_comm);
            end_timer!(output_comm_time);
        }
        // //--------------------------------------------------------
        // //test cell: Test that the beaver multiplication works.
        let mut server_output_shares = vec![];
        for i in 0..mpc_cfg.num_parties {
            server_output_shares.push(servers[i].server_outputs[0]);
        }
        let mul_res = interpolate_shares(&preproc, server_output_shares, mpc_cfg).unwrap();
        assert_eq!(mul_res, clients[0].input[0].mul(&clients[1].input[0]));
        // //-------------------------------------------------------

        // Step 4b: Send partial comms to all servers. Commit to the outputs of the circuit
        // Ideally this commitment should be a threshold signature for now. But we are
        // ignoring this aspect for now.
        // Collect all random_shares for marlin prover step
        // Collect all input shares and check that they are consistent
        let mut rand_assignments = vec![];
        let init_round_bytes_sent =
            pec_round_comm_size(&server_inp_comms[0]) + pec_round_comm_size(&server_opt_comms[0]);
        let init_comm_time = start_timer!(|| "Initial Commitment and Output Check time");
        let total_delay = 10.0_f64.powi(6i32) * COMM_LATENCY
            + ((init_round_bytes_sent * 8) as f64) / (COMM_BANDWIDTH * 10.0_f64.powi(6i32))
                * 10.0_f64.powi(9i32);
        let sec_delay = (total_delay / (10u64.pow(9u32) as f64)) as u64;
        let nano_delay = ((total_delay as u64) - sec_delay * 10u64.pow(9u32)) as u32;
        sleep(Duration::new(sec_delay, nano_delay));

        let cli_inp_comm_from_server =
            pec_batch_interpolate_shares_exponent(&preproc, &server_inp_comms, mpc_cfg).unwrap();
        // dbg!(&cli_inp_comm_from_server[0]);
        for comm_iter in 0..cli_inp_comm_from_server.len() {
            assert_eq!(
                cli_inp_comm_from_server[comm_iter].commitment().comm,
                cli_inp_comms[comm_iter].commitment().comm
            );
        }
        let server_output_com = servers[0]
            .combine_pec_output_comm(&preproc, &server_opt_comms, mpc_cfg)
            .unwrap();
        end_timer!(init_comm_time);

        for i in 0..mpc_cfg.num_parties {
            rand_assignments.push(servers[i].client_rand_inputs.clone());
        }
        cli_inp_comms.extend(server_output_com);
        let statement_comms = cli_inp_comms;

        //Create the final statement commitment
        let mut final_stmt_comms = vec![PECPolycommit::commit_to_one(&pec_ck)];
        final_stmt_comms.extend(statement_comms);

        let final_stmt_comm =
            PECPolycommit::pec_interpolate("x_poly".to_owned(), final_stmt_comms.clone());
        // Step 5: Marlin proof
        // let _a = Fr::from_repr(BigInteger256::from(1));
        let mut c = a;
        c.mul_assign(&b);
        let proof = MarlinInst::prove(
            &index_pk,
            *final_stmt_comm.commitment(),
            &rand_assignments,
            &preproc,
            mpc_cfg,
            solved_circuits,
            rng,
        )
        .unwrap();
        println!("Called prover");

        let auditor_avg_time = start_timer!(|| "Auditer average time");
        for _ in 0..10 {
            assert!(MarlinInst::audit(&index_vk, final_stmt_comms.clone(), &proof, rng).unwrap());
            println!("Called auditor");
        }
        end_timer!(auditor_avg_time);
    }

    use std::env;
    use std::process::Command;
    #[test]
    fn bench_logrank() {
        // Either supply all env variables or none.

        // Left the first ARg for -- --nocapture.
        // Maybe have a key-value style arg
        let num_bits: usize = env::var("NUM_BITS")
            .unwrap_or("60".to_owned())
            .parse()
            .expect("Num Constraints must be number");
        let stmt_len = env::var("NUM_CLIENTS")
            .unwrap_or("1".to_owned())
            .parse()
            .expect("Stmt len must be number");
        let num_variables = stmt_len + 2;
        let num_servers = env::var("NUM_SERVERS")
            .unwrap_or("1".to_owned())
            .parse()
            .expect("Num MPC servers must be number");
        let num_constraints: usize = 65530;
        let output = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let git_hash = String::from_utf8(output.stdout).unwrap();

        println!("Git hash:{}", git_hash);
        println!("Running Auditable MPC test");
        println!("statement length:{}", stmt_len,);
        println!("Number of constraints:{}", num_constraints);
        println!("Number of servers:{}", num_servers);
        println!("Number of bits: {}", num_bits);

        test_logrank(
            num_constraints,
            num_variables,
            num_servers,
            stmt_len,
            num_bits,
        );
    }

    #[test]
    fn bench_random_circuits() {
        // Either supply all env variables or none.

        // Left the first ARg for -- --nocapture.
        // Maybe have a key-value style arg
        let num_constraints: usize = env::var("NUM_CONSTRAINTS")
            .unwrap_or("1024".to_owned())
            .parse()
            .expect("Num Constraints be number");
        let stmt_len = env::var("STMT_LEN")
            .unwrap_or("64".to_owned())
            .parse()
            .expect("Stmt len be number");
        let num_variables = stmt_len + 2;
        let num_servers = env::var("NUM_SERVERS")
            .unwrap_or("1".to_owned())
            .parse()
            .expect("Num MPC servers be number");

        let output = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let git_hash = String::from_utf8(output.stdout).unwrap();

        println!("Git hash:{}", git_hash);
        println!("Running Auditable MPC test");
        println!("statement length:{}", stmt_len,);
        println!("Number of constraints:{}", num_constraints);
        println!("Number of servers:{}", num_servers);

        test_auditable_mpc(num_constraints, num_variables, num_servers, stmt_len);
    }

    #[test]
    fn bench_auction() {
        // Either supply all env variables or none.

        // Left the first ARg for -- --nocapture.
        // Maybe have a key-value style arg
        let num_bits: usize = env::var("NUM_BITS")
            .unwrap_or("60".to_owned())
            .parse()
            .expect("Num Constraints must be number");
        let stmt_len = env::var("NUM_CLIENTS")
            .unwrap_or("128".to_owned())
            .parse()
            .expect("Stmt len must be number");
        let num_variables = stmt_len + 2;
        let num_servers = env::var("NUM_SERVERS")
            .unwrap_or("1".to_owned())
            .parse()
            .expect("Num MPC servers must be number");
        let num_constraints: usize = num_bits*stmt_len*2 + stmt_len*8;
        let output = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let git_hash = String::from_utf8(output.stdout).unwrap();

        println!("Git hash:{}", git_hash);
        println!("Running Auditable MPC test");
        println!("statement length:{}", stmt_len,);
        println!("Number of constraints:{}", num_constraints);
        println!("Number of servers:{}", num_servers);
        println!("Number of bits: {}", num_bits);

        test_auction(num_constraints, num_variables, num_servers, stmt_len, num_bits);
    }
}
