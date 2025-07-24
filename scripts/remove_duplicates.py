#!/usr/bin/env python3
import json
import sys
import argparse
from typing import List, Dict, Any

def remove_duplicates(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate entries from JSON data."""
    unique_data = []
    seen = set()
    duplicates_count = 0
    
    for idx, item in enumerate(data):
        # Convert dict to a hashable string representation
        item_str = json.dumps(item, sort_keys=True)
        
        if item_str not in seen:
            seen.add(item_str)
            unique_data.append(item)
        else:
            duplicates_count += 1
            print(f"Found duplicate at index {idx}: contract_name={item.get('contract_name', 'N/A')}")
    
    return unique_data, duplicates_count

def main():
    parser = argparse.ArgumentParser(description='Remove duplicate entries from JSON file')
    parser.add_argument('input_file', help='Path to input JSON file')
    parser.add_argument('-o', '--output', help='Output file path (default: input_file with .dedup suffix)', 
                        default=None)
    
    args = parser.parse_args()
    
    # Set output file
    if args.output is None:
        args.output = f"{args.input_file}.dedup"
    
    print(f"Reading from: {args.input_file}")
    
    try:
        # Read JSON file
        with open(args.input_file, 'r') as f:
            data = json.load(f)
        
        print(f"Total entries: {len(data)}")
        
        # Remove duplicates
        unique_data, duplicates_count = remove_duplicates(data)
        
        # Write deduplicated data as JSON array (like original)
        with open(args.output, 'w') as f:
            json.dump(unique_data, f, separators=(',', ':'))
        
        # Summary
        print("\n" + "="*50)
        print("SUMMARY")
        print("="*50)
        print(f"Original entries: {len(data)}")
        print(f"Duplicates found: {duplicates_count}")
        print(f"Unique entries: {len(unique_data)}")
        print(f"Output written to: {args.output}")
        
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found!")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{args.input_file}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()