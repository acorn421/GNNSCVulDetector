#!/usr/bin/env python
"""
SmartInject Comparison Tool

Usage:
    smartinject-compare.py single <dir> [--verbose] [--exp_name=<name>]
    smartinject-compare.py multi <dir> [--verbose] [--exp_name=<name>]
    smartinject-compare.py -h | --help

Options:
    -h --help          Show this screen.
    --verbose          Enable verbose output and save CSV files.
    --exp_name=<name>  Experiment name for output files.

Commands:
    single  Compare train.json vs smartinject_train.json in a single directory
    multi   Run single mode on multiple subdirectories (1, 2, 3, etc.)
"""

import os
import sys
import subprocess
import json
import csv
import re
from docopt import docopt
from datetime import datetime
from pathlib import Path


class SmartInjectCompare:
    def __init__(self, verbose=False, exp_name=None):
        self.verbose = verbose
        self.exp_name = exp_name if exp_name else datetime.now().strftime("%Y%m%d_%H%M%S")

    def parse_results_csv(self, csv_file_path):
        """Parse the results CSV file to extract metrics."""
        try:
            with open(csv_file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # CSV only has one row with best F1 metrics
                    return {
                        'best_f1_metrics': {
                            'epoch': int(float(row['epoch'])),
                            'accuracy': float(row['accuracy']),
                            'precision': float(row['precision']),
                            'recall': float(row['recall']),
                            'f1': float(row['f1'])
                        }
                    }
        except Exception as e:
            print(f"Error parsing CSV file {csv_file_path}: {e}")
            return None

    def run_training(self, train_file, test_file, exp_suffix):
        """Run GNNSCModel.py with specified training and test files."""
        exp_name_full = f'{self.exp_name}_{exp_suffix}'

        cmd = [
            'python', 'GNNSCModel.py',
            '--train-file', train_file,
            '--valid-file', test_file,
            '--exp_name', exp_name_full
        ]

        if self.verbose:
            cmd.append('--verbose')

        print(f"\n{'='*60}")
        print(f"Running training with {exp_suffix}")
        print(f"Train file: {train_file}")
        print(f"Test file: {test_file}")
        print(f"Experiment name: {exp_name_full}")
        print(f"{'='*60}\n")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            # Print output in real-time style
            print(result.stdout)

            if result.stderr:
                print("Errors:", result.stderr)

            # Parse the CSV file instead of stdout
            csv_file = f'res_{exp_name_full}.csv'
            if os.path.exists(csv_file):
                return self.parse_results_csv(csv_file)
            else:
                print(f"Warning: Results CSV file {csv_file} not found")
                return None

        except Exception as e:
            print(f"Error running training: {e}")
            return None

    def format_comparison(self, before_metrics, after_metrics):
        """Format the comparison results for display."""
        output = []
        output.append("\n" + "="*70)
        output.append("                    COMPARISON RESULTS")
        output.append("="*70)

        # F1 Score comparison
        output.append("\n📊 BEST F1 SCORE COMPARISON:")
        output.append("-"*50)

        if before_metrics and after_metrics:
            before_f1 = before_metrics.get('best_f1_metrics', {}) if before_metrics else {}
            after_f1 = after_metrics.get('best_f1_metrics', {}) if after_metrics else {}

            # F1 Score
            before_f1_score = before_f1.get('f1', 0)
            after_f1_score = after_f1.get('f1', 0)
            f1_change = after_f1_score - before_f1_score
            f1_change_pct = (f1_change / before_f1_score * 100) if before_f1_score > 0 else 0

            output.append(f"  F1 Score:")
            output.append(f"    • Before (train.json):           {before_f1_score:.5f}")
            output.append(f"    • After (smartinject_train.json): {after_f1_score:.5f}")
            output.append(f"    • Change: {f1_change:+.5f} ({f1_change_pct:+.2f}%)")

            # Accuracy
            before_acc = before_f1.get('accuracy', 0)
            after_acc = after_f1.get('accuracy', 0)
            acc_change = after_acc - before_acc

            output.append(f"\n  Accuracy:")
            output.append(f"    • Before: {before_acc:.5f}")
            output.append(f"    • After:  {after_acc:.5f}")
            output.append(f"    • Change: {acc_change:+.5f}")

            # Precision
            before_prec = before_f1.get('precision', 0)
            after_prec = after_f1.get('precision', 0)
            prec_change = after_prec - before_prec

            output.append(f"\n  Precision:")
            output.append(f"    • Before: {before_prec:.5f}")
            output.append(f"    • After:  {after_prec:.5f}")
            output.append(f"    • Change: {prec_change:+.5f}")

            # Recall
            before_rec = before_f1.get('recall', 0)
            after_rec = after_f1.get('recall', 0)
            rec_change = after_rec - before_rec

            output.append(f"\n  Recall:")
            output.append(f"    • Before: {before_rec:.5f}")
            output.append(f"    • After:  {after_rec:.5f}")
            output.append(f"    • Change: {rec_change:+.5f}")

            # Epoch information
            output.append(f"\n  Best Epochs:")
            output.append(f"    • Before: Epoch {before_f1.get('epoch', 'N/A')}")
            output.append(f"    • After:  Epoch {after_f1.get('epoch', 'N/A')}")

            # Summary
            output.append("\n" + "="*70)
            output.append("                         SUMMARY")
            output.append("="*70)

            if f1_change > 0:
                output.append(f"✅ SmartInject IMPROVED F1 score by {f1_change:.5f} ({f1_change_pct:.2f}%)")
            elif f1_change < 0:
                output.append(f"❌ SmartInject DECREASED F1 score by {abs(f1_change):.5f} ({abs(f1_change_pct):.2f}%)")
            else:
                output.append("➖ SmartInject resulted in NO CHANGE to F1 score")

        else:
            output.append("Error: Could not extract metrics from one or both training runs")

        output.append("="*70 + "\n")

        return "\n".join(output)

    def save_results(self, directory, before_metrics, after_metrics, comparison_text):
        """Save the comparison results to a text file."""
        output_file = os.path.join(directory, f'comparison_results_{self.exp_name}.txt')

        with open(output_file, 'w') as f:
            f.write(f"SmartInject Comparison Results\n")
            f.write(f"Directory: {directory}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"\n{comparison_text}\n")

            # Also save raw metrics as JSON
            f.write("\n\n" + "="*70 + "\n")
            f.write("RAW METRICS (JSON):\n")
            f.write("="*70 + "\n")
            if before_metrics:
                f.write("\nBefore (train.json):\n")
                f.write(json.dumps(before_metrics, indent=2))
            if after_metrics:
                f.write("\n\nAfter (smartinject_train.json):\n")
                f.write(json.dumps(after_metrics, indent=2))

        print(f"\n💾 Results saved to: {output_file}")

    def run_single(self, directory):
        """Run comparison for a single directory."""
        # Check if required files exist
        train_file = os.path.join(directory, 'train.json')
        smartinject_train_file = os.path.join(directory, 'smartinject_train.json')
        test_file = os.path.join(directory, 'test.json')

        for file in [train_file, smartinject_train_file, test_file]:
            if not os.path.exists(file):
                print(f"❌ Error: Required file not found: {file}")
                return False

        print(f"\n🚀 Starting comparison for directory: {directory}")

        # Run training with original train.json
        before_metrics = self.run_training(train_file, test_file, 'before')

        # Run training with smartinject_train.json
        after_metrics = self.run_training(smartinject_train_file, test_file, 'after')

        # Compare results
        comparison = self.format_comparison(before_metrics, after_metrics)
        print(comparison)

        # Save results
        self.save_results(directory, before_metrics, after_metrics, comparison)

        return True

    def run_multi(self, directory):
        """Run comparison for multiple subdirectories."""
        print(f"\n🔄 Running multi-mode for directory: {directory}")

        # Find all numbered subdirectories
        subdirs = []
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path) and item.isdigit():
                subdirs.append(item)

        subdirs.sort(key=int)  # Sort numerically

        if not subdirs:
            print(f"❌ No numbered subdirectories found in {directory}")
            return False

        print(f"📁 Found {len(subdirs)} subdirectories: {', '.join(subdirs)}")

        results = []
        for subdir in subdirs:
            subdir_path = os.path.join(directory, subdir)
            print(f"\n{'='*70}")
            print(f"Processing subdirectory: {subdir}")
            print(f"{'='*70}")

            # Update exp_name for each subdirectory
            original_exp_name = self.exp_name
            self.exp_name = f"{original_exp_name}_dir{subdir}"

            success = self.run_single(subdir_path)
            results.append((subdir, success))

            # Restore original exp_name
            self.exp_name = original_exp_name

        # Print summary
        print("\n" + "="*70)
        print("                    MULTI-MODE SUMMARY")
        print("="*70)

        for subdir, success in results:
            status = "✅ Success" if success else "❌ Failed"
            print(f"  Directory {subdir}: {status}")

        print("="*70 + "\n")

        return True


def main():
    args = docopt(__doc__)

    verbose = args.get('--verbose', False)
    exp_name = args.get('--exp_name', None)

    compare = SmartInjectCompare(verbose=verbose, exp_name=exp_name)

    if args['single']:
        directory = args['<dir>']
        if not os.path.exists(directory):
            print(f"❌ Error: Directory not found: {directory}")
            sys.exit(1)
        compare.run_single(directory)

    elif args['multi']:
        directory = args['<dir>']
        if not os.path.exists(directory):
            print(f"❌ Error: Directory not found: {directory}")
            sys.exit(1)
        compare.run_multi(directory)


if __name__ == "__main__":
    main()