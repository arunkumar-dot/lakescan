//! Keeps README.md honest about the two public contracts it documents:
//! every rule code and every exit code must appear in it. Adding a rule or
//! an exit code without documenting it fails this test.

use lakescan::ExitCode;
use lakescan::model::RuleId;

const README: &str = include_str!("../README.md");

#[test]
fn every_rule_code_is_documented() {
    for rule in RuleId::ALL {
        let code = format!("`{}`", rule.code());
        assert!(
            README.contains(&code),
            "README.md does not mention rule {code}"
        );
    }
}

#[test]
fn every_exit_code_is_documented_in_the_exit_code_table() {
    for code in ExitCode::ALL {
        // A row of the exit-code table: `| 2 | `Usage` | ... |`.
        let row = format!("\n| {} | `{code:?}` |", code.as_i32());
        assert!(
            README.contains(&row),
            "README.md has no exit-code table row starting {row:?}"
        );
    }
}
