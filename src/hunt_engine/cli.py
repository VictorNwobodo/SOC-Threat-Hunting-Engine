import argparse
from pathlib import Path
from hunt_engine.pipeline import run_ingestion
from hunt_engine.reconciler import reconcile_discrepancies
from hunt_engine.hunts import run_hunts
from hunt_engine.benchmark import generate_benchmark

def main():
    parser = argparse.ArgumentParser(description="UBI Stage 5 SOC Production Hunt Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Command: build-input
    build_parser = subparsers.add_parser("build-input")
    build_parser.add_argument("raw_dir", type=Path, help="Path to raw evidence directory")
    build_parser.add_argument("work_dir", type=Path, help="Path to work directory")

    # Command: reconcile
    rec_parser = subparsers.add_parser("reconcile")
    rec_parser.add_argument("discrepancy_file", type=Path, help="Path to discrepancy.json")
    rec_parser.add_argument("work_dir", type=Path, help="Path to work directory")

    # Command: hunt
    hunt_parser = subparsers.add_parser("hunt")
    hunt_parser.add_argument("work_dir", type=Path, help="Path to work directory")
    hunt_parser.add_argument("queries_dir", type=Path, help="Path to queries directory")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark")

    args = parser.parse_args()

    if args.command == "build-input":
        run_ingestion(args.raw_dir, args.work_dir, Path("evidence"))
    elif args.command == "reconcile":
        reconcile_discrepancies(args.discrepancy_file, args.work_dir, Path("evidence"))
    elif args.command == "hunt":
        run_hunts(args.work_dir, args.queries_dir, Path("evidence"))
    elif args.command == "benchmark":
        generate_benchmark(
            Path("raw/evidence"),
            Path("work"),
            Path("queries"),
            Path("raw/private/discrepancy.json"),
            Path("evidence")
        )
    else:
        parser.print_help()

if __name__ == "__main__":
    main()