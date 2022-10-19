/// Defines a common test harness that can be used in various packages
#[macro_export]
macro_rules! inegration_test_main {
    // No setup or teardown
    ($cli_args:ty, $test_args:ty) => {
        integration_test_main!($cli_args, $test_args, |_| {}, |_| {});
    };

    // Setup only
    ($cli_args:ty, $test_args:ty, $setup:ident) => {
        integration_test_main!($cli_args, $test_args, $setup, |_| {});
    };

    // Allows both setup and teardown
    ($cli_args:ty, $test_args:ty, $setup:ident, $teardown:ident) => {
        use std::{borrow::Borrow, cell::RefCell, net::SocketAddr, process::exit, rc::Rc};

        use clap::Parser;
        use colored::Colorize;
        use dns_lookup::lookup_host;

        // Collect the statically defined tests into an interable
        inventory::collect!(IntegrationTest);

        #[allow(unused_doc_comments, clippy::await_holding_refcell_ref)]
        #[tokio::main]
        async fn main() {
            /**
             * Setup
             */
            let args = $cli_args::parse();

            // Call the setup callback if requested
            $setup(args);

            /**
             * Test harness
             */
            if args.verbose {
                println!("\n\n{}\n", "Running integration tests...".blue());
            }

            // Assumed From<$cli_args> is implemented for $test_args
            let test_args: $test_args = args.into()
            let mut all_success = true;

            for test in inventory::iter::<IntegrationTest> {
                if args.borrow().test.is_some()
                    && args.borrow().test.as_deref().unwrap() != test.name
                {
                    continue;
                }

                if args.verbose {
                    print!("Running {}... ", test.name);
                }
                let res: Result<(), String> = (test.test_fn)(&test_args);
                all_success &= validate_success(res, args.party);
            }

            // Call macro caller defined teardown
            $teardown();

            if all_success {
                if args.verbose == 0 {
                    println!("\n{}", "Integration tests successful!".green(),);
                }

                exit(0);
            }

            exit(-1);
        }
    };
}
