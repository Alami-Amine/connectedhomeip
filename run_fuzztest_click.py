import enum
import logging
import os
import re
import subprocess

import click
import coloredlogs

profile_output_folder = "out/profiling_fuzztest"
coverage_report_output_folder = "out/coverage_fuzztest"


class FuzzTestMode(enum.Enum):
    UNIT_TEST_MODE = enum.auto()
    CONTINUOUS_FUZZ_MODE = enum.auto()


def list_fuzz_test_binaries():
    """Lists all compiled fuzz tests in the 'out' directory."""
    build_dir = "out"
    if not os.path.isdir(build_dir):
        logging.error(f"Error: Build directory '{build_dir}' does not exist.")
        return []

    fuzz_tests = []
    for root, _, files in os.walk(build_dir):
        for file in files:
            if file.startswith("fuzz-") and os.access(os.path.join(root, file), os.X_OK) and "chip_pw_fuzztest" in root.split(os.sep):
                fuzz_tests.append(os.path.join(root, file))
    return fuzz_tests


def get_fuzz_test_cases(fuzz_test_binary_path):
    """Executes the fuzz test binary (i.e. Fuzz Test Suite) with --list_fuzz_tests to print the list of all available FUZZ_TEST-s (i.e. Test Cases)"""
    try:
        logging.debug(f"\nfuzz_test_path = {fuzz_test_binary_path}\n")
        result = subprocess.run([fuzz_test_binary_path, "--list_fuzz_tests"], capture_output=True, text=True)
        output = result.stdout
        if output:
            test_cases = re.findall(r'test:\s*(\S+)', output)
            return test_cases

        else:
            logging.info("No test cases found.")
            return []
    except Exception as e:
        logging.error(f"Error executing {fuzz_test_binary_path}: {e}")
        return []


def run_fuzz_test(fuzz_test_binary_path, selected_fuzz_test_case, coverage_output_base_name, run_mode):
    """Runs the fuzz test and generates an LLVM profile file."""

    env = os.environ.copy()
    profraw_file = f"{profile_output_folder}/{coverage_output_base_name}.profraw"
    env["LLVM_PROFILE_FILE"] = profraw_file

    try:
        if run_mode == FuzzTestMode.UNIT_TEST_MODE:
            subprocess.run([fuzz_test_binary_path, ], env=env, check=True)
            logging.info(f"Fuzz Test Suite executed in Unit Test Mode. Profile saved to {profraw_file}")

        elif run_mode == FuzzTestMode.CONTINUOUS_FUZZ_MODE:
            subprocess.run([fuzz_test_binary_path, f"--fuzz={selected_fuzz_test_case}"], env=env, check=True)

    # in FuzzTestMode.CONTINUOUS_FUZZ_MODE, the fuzzing will run indefinitely until stopped by the user
    except KeyboardInterrupt:
        logging.info(f"\nFuzzing Stopped. Profile saved to {profraw_file}. Generating coverage report...")

    except Exception as e:
        logging.error(f"Error running fuzz test: {e}")


def generate_coverage_report(fuzz_test_binary_path, coverage_output_base_name, output_dir):
    """Generates an HTML coverage report."""

    coverage_subfolder = f"{coverage_report_output_folder}/{coverage_output_base_name}"

    profraw_file = f"{profile_output_folder}/{coverage_output_base_name}.profraw"
    profdata_file = f"{profile_output_folder}/{coverage_output_base_name}.profdata"
    lcov_trace_file = f"{profile_output_folder}/{coverage_output_base_name}.info"

    if not os.path.exists(profraw_file):
        logging.error(f"Profile raw file not found: {profraw_file}")
        return False

    # Step1 Merge the profile data
    subprocess.run(["llvm-profdata", "merge", "-sparse", profraw_file, "-o", profdata_file], check=True)
    logging.info(f"Profile data merged into {profdata_file}")

    # Step2 Exports coverage data into lcov trace file format.
    cmd = [
        "llvm-cov",
        "export",
        "-format=lcov",
        "--instr-profile",
        profdata_file,
        fuzz_test_binary_path
    ]

    # for -ignore-filename-regex
    ignore_paths = [
        "third_party/.*",
        "/usr/include/.*",
        "/usr/lib/.*",
    ]
    for p in ignore_paths:
        cmd.append("-ignore-filename-regex")
        cmd.append(p)

    with open(lcov_trace_file, "w") as file:
        subprocess.run(cmd, stdout=file, stderr=file)

    # Step3 Generate the coverage report
    cmd = ["genhtml"]

    errors_to_ignore = [
        "inconsistent", "source"
    ]
    for e in errors_to_ignore:
        cmd.append("--ignore-errors")
        cmd.append(e)

    flat = False
    cmd.append("--flat" if flat else "--hierarchical")
    cmd.append("--synthesize-missing")
    cmd.append("--output-directory")
    cmd.append(f"{coverage_subfolder}")
    cmd.append(f"{lcov_trace_file}")

    subprocess.run(cmd, check=True)
    logging.info(f"Coverage report generated in {coverage_subfolder}")


@click.command()
@click.option("--fuzz-test", help="Specific fuzz test binary to run. If not provided, lists available test binaries.")
@click.option("--output", default="html_report", help="Directory for the coverage report.")
def main(fuzz_test, output):

    coloredlogs.install(
        level="DEBUG",
        fmt="%(message)s",
        level_styles={
            "debug": {"color": "cyan"},
            "info": {"color": "green"},
            "error": {"color": "red"},
        },
    )

    logging.info("\nThis Script is Designed to be Run with Google FuzzTests built with coverage enabled.\n")
    fuzz_tests = list_fuzz_test_binaries()

    if not fuzz_tests:
        logging.info("No pigweedw-based FuzzTests found.")
        return

    if not fuzz_test:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        logging.info("\nAvailable Fuzz Test Binaries (each Binary can have multiple FUZZ_TESTs/TestCases): \n")
        for test in fuzz_tests:
            logging.info(f"{test}")
        return

    # this allows me to match any name, consider removing it
    selected_fuzz_test_binary = next((test for test in fuzz_tests if fuzz_test in test), None)
    logging.debug(f"selected_fuzz_test_binary = {selected_fuzz_test_binary}")

    if not selected_fuzz_test_binary:
        logging.error(f"Error: Fuzz test '{fuzz_test}' not found.")
        return

    test_cases = get_fuzz_test_cases(selected_fuzz_test_binary)

    if test_cases:
        selected_fuzz_test_case = []
        logging.info("Available test cases:")
        for i, case in enumerate(test_cases, start=1):
            logging.info(f"{i}. {case}")
        logging.info("\nEnter 0 to run all test cases in Unit Test Mode (just a few seconds of each FUZZ_TEST(testcase)\n")

        choice = click.prompt("Enter the number of the test case to run", type=int)
        if 1 <= choice <= len(test_cases):
            run_fuzztest_mode = FuzzTestMode.CONTINUOUS_FUZZ_MODE

            selected_fuzz_test_case = test_cases[choice - 1]

            # Use the FuzzTest (Test Case) Name  as the name for coverage output
            coverage_output_base_name = "{}".format(selected_fuzz_test_case.replace('.', "_"))

        elif choice == 0:
            run_fuzztest_mode = FuzzTestMode.UNIT_TEST_MODE

            # Use the FuzzTest Suite Name as the name for coverage output
            coverage_output_base_name = f"{test_cases[choice - 1].split('.')[0]}"

            pass
        else:
            logging.info("Invalid choice. Exiting.")
            return

    # make the profraw use the testcase/FUZZ_TEST name: e.g. FuzzCASE_HandleSigma1

    try:
        logging.info(f"Running fuzz test: {fuzz_test}")
        run_fuzz_test(selected_fuzz_test_binary, selected_fuzz_test_case, coverage_output_base_name, run_fuzztest_mode)
    finally:
        generate_coverage_report(fuzz_test, coverage_output_base_name, output)


if __name__ == "__main__":
    main()
