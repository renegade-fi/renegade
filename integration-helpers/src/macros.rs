//! Groups test related helper macros into a module

/// Defines a common test harness that can be used in various packages
#[macro_export]
macro_rules! integration_test_main {
    // No setup or teardown
    ($cli_args:ty, $test_args:ty) => {
        fn generic_noop<ARGS>(_: &ARGS) {}
        integration_test_main!($cli_args, $test_args, generic_noop);
    };

    // Setup only
    ($cli_args:ty, $test_args:ty, $setup:ident) => {
        fn generic_noop_no_args() {}
        integration_test_main!($cli_args, $test_args, $setup, generic_noop_no_args);
    };

    // Allows both setup and teardown
    ($cli_args:ty, $test_args:ty, $setup:ident, $teardown:ident) => {
        use std::{borrow::Borrow, cell::RefCell, net::SocketAddr, process::exit, rc::Rc};

        use colored::Colorize;
        use dns_lookup::lookup_host;
        use inventory::ctor;
        use std::io::{stdout, Write};

        use $crate::types::IntegrationTest;

        /// Defines a wrapper type around the test args so that the macro caller can take
        /// inventory on the IntegrationTest type which is owned by the `integration-helpers`
        /// package.
        ///
        /// This is necessary because the inventory::collect macro implements a foreign trait
        /// on the type it accepts
        struct TestWrapper(IntegrationTest<$test_args>);

        // Collect the statically defined tests into an iterable
        inventory::collect!(TestWrapper);

        /// Defines a secondary CLI that allows the test harness to simply no-op if `--skip integration`
        /// is passed. This is useful when running only unit tests from the workspace level, i.e.:
        ///     cargo test --workspace -- --skip integration
        /// will properly skip tests run by this harness

        #[derive(Debug, Clone, Parser)]
        #[command(author, version, about, long_about=None)]
        struct SkipCLI {
            /// The skip filter placed on the tests
            #[arg(long, value_parser)]
            skip: String,
        }

        #[allow(unused_doc_comments, clippy::await_holding_refcell_ref)]
        #[tokio::main]
        async fn main() {
            /**
             * Setup
             */
            // Skip tests if the only CLI argument is --skip integration
            let skip_args = SkipCLI::try_parse();
            if skip_args.map_or(false, |x| x.skip == "integration") {
                return;
            }

            let args = <$cli_args>::parse();

            // Call the setup callback if requested
            $setup(&args);

            /**
             * Test harness
             */
            let verbose = args.verbose;
            if verbose {
                println!("\n\n{}\n", "Running integration tests...".blue());
            }

            // Assumed From<$cli_args> is implemented for $test_args
            let test_args: $test_args = args.clone().into();
            let mut all_success = true;

            for test_wrapper in inventory::iter::<TestWrapper> {
                let test = test_wrapper.0.clone();
                if args.borrow().test.is_some()
                    && args.borrow().test.as_deref().unwrap() != test.name
                {
                    continue;
                }

                if verbose {
                    // Flush the write buffer before the test executes. We print success or failure on the same
                    // line as the "Running", but if the test panics, we want to know which test was run
                    print!("Running {}... ", test.name);
                    stdout().flush().unwrap();
                }
                let res: Result<(), String> = (test.test_fn)(&test_args);
                all_success &= validate_success(res, verbose);
            }

            // Call macro caller defined teardown
            $teardown();

            if all_success {
                if verbose {
                    println!("\n{}", "Integration tests successful!".green(),);
                }

                exit(0);
            }

            exit(-1);
        }

        /// Prints a success or failure message, returns true if success, false if failure
        #[inline]
        fn validate_success(res: Result<(), String>, verbose: bool) -> bool {
            if res.is_ok() {
                if verbose {
                    println!("{}", "Success!".green());
                }

                true
            } else {
                println!("{}\n\t{}", "Failure...".red(), res.err().unwrap());
                false
            }
        }
    };
}
