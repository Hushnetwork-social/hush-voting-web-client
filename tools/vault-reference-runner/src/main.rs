//! HushVault v1 independent non-production reference validator (FEAT-003).
//!
//! Exit categories: 0 pass, 1 mismatch, 2 invalid corpus/arguments, 3 internal failure.
//! Diagnostics contain stable categories and digest-only report fields.

mod jcs;
mod report;
mod strict_json;
mod suite;
mod vectors;

use std::env;
use std::process::ExitCode;

#[derive(Default)]
struct Options {
    corpus: Option<String>,
    check: bool,
    report_path: Option<String>,
    expected_manifest_sha256: Option<String>,
}

fn usage() {
    eprintln!(
        "usage: vault-reference-runner --corpus <path> --check [--expected-manifest-sha256 <hex>] [--report <path>]"
    );
}

fn parse_options(arguments: &[String]) -> Result<Options, ()> {
    let mut options = Options::default();
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--corpus" => {
                index += 1;
                options.corpus = arguments.get(index).cloned();
                if options.corpus.is_none() {
                    return Err(());
                }
            }
            "--check" => options.check = true,
            "--report" => {
                index += 1;
                options.report_path = arguments.get(index).cloned();
                if options.report_path.is_none() {
                    return Err(());
                }
            }
            "--expected-manifest-sha256" => {
                index += 1;
                options.expected_manifest_sha256 = arguments.get(index).cloned();
                if options.expected_manifest_sha256.is_none() {
                    return Err(());
                }
            }
            "--version" if arguments.len() == 2 => {
                println!(
                    "vault-reference-runner {} (corpus-contract 1.0.0)",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(Options {
                    check: true,
                    corpus: Some(String::new()),
                    ..Options::default()
                });
            }
            _ => return Err(()),
        }
        index += 1;
    }
    Ok(options)
}

fn execute(options: Options) -> ExitCode {
    if options.corpus.as_deref() == Some("") {
        return ExitCode::SUCCESS;
    }
    let Some(corpus_path) = options.corpus else {
        usage();
        return ExitCode::from(2);
    };
    if !options.check {
        eprintln!("vault-reference-runner: invalid arguments");
        return ExitCode::from(2);
    }

    let validation = std::panic::catch_unwind(|| {
        if cfg!(debug_assertions) && env::var_os("HUSH_VAULT_RUNNER_TEST_PANIC").is_some() {
            panic!("contained non-production test panic");
        }
        vectors::run_corpus_validation(&corpus_path, options.expected_manifest_sha256.as_deref())
    });
    match validation {
        Ok(Ok(report)) => {
            if let Some(path) = options.report_path {
                if report::write_report(&path, &report).is_err() {
                    eprintln!("vault-reference-runner: internal failure: report-write-failed");
                    return ExitCode::from(3);
                }
            }
            println!("{}", report::render_summary(&report));
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Ok(Err(error)) => match error {
            vectors::RunnerError::Corpus => {
                eprintln!(
                    "vault-reference-runner: invalid corpus: {}",
                    error.message()
                );
                ExitCode::from(2)
            }
            vectors::RunnerError::Internal => {
                eprintln!(
                    "vault-reference-runner: internal failure: {}",
                    error.message()
                );
                ExitCode::from(3)
            }
        },
        Err(_) => {
            eprintln!("vault-reference-runner: internal failure: panic-contained");
            ExitCode::from(3)
        }
    }
}

fn main() -> ExitCode {
    // Suppress the default panic payload because it may contain implementation details;
    // `execute` emits a stable redacted category after containment.
    std::panic::set_hook(Box::new(|_| {}));
    let arguments: Vec<String> = env::args().collect();
    match parse_options(&arguments) {
        Ok(options) => execute(options),
        Err(()) => {
            usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_arguments() {
        let arguments = vec!["runner".to_owned(), "--unknown".to_owned()];
        assert!(parse_options(&arguments).is_err());
    }

    #[test]
    fn parses_manifest_pin_and_report() {
        let arguments = vec![
            "runner".to_owned(),
            "--corpus".to_owned(),
            "corpus".to_owned(),
            "--check".to_owned(),
            "--expected-manifest-sha256".to_owned(),
            "a".repeat(64),
            "--report".to_owned(),
            "report.json".to_owned(),
        ];
        let options = parse_options(&arguments).expect("valid options");
        assert!(options.check);
        assert_eq!(options.corpus.as_deref(), Some("corpus"));
        assert_eq!(options.report_path.as_deref(), Some("report.json"));
    }
}
