use gate_observation_macros::observed_function;

observed_function!(plain, false);
observed_function!(branch, true);
observed_function!(unexecuted, true);
#[cfg(feature = "branching")]
observed_function!(configured, true);
#[cfg(not(feature = "branching"))]
observed_function!(configured, false);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_functions_execute_real_code() {
        assert_eq!(plain(-3), -3);
        assert_eq!(branch(2), 1);
        assert_eq!(branch(-2), 0);
        // Deliberately never execute `unexecuted` for future coverage mapping tests.
    }
    #[test]
    fn configuration_selects_the_actual_invocation() {
        assert_eq!(
            configured(7),
            if cfg!(feature = "branching") { 1 } else { 7 }
        );
    }
}
