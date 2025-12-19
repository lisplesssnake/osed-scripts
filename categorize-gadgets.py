#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict


class GadgetCategorizer:
    def __init__(self, input_file, arch, output_dir):
        self.input_file = input_file
        self.arch = arch
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.gadgets = []
        self.categories = defaultdict(list)
        self.load_gadgets()
    
    def load_gadgets(self):
        """Load gadgets from rp++ output file"""
        print(f"[+] Loading gadgets from {self.input_file}")
        
        with open(self.input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('0x'):
                    continue
                
                # Parse: "0x10001234: instruction; instruction; ret;"
                parts = line.split(':', 1)
                if len(parts) != 2:
                    continue
                
                address = parts[0].strip()
                instructions = parts[1].strip()
                
                self.gadgets.append({
                    'address': address,
                    'instructions': instructions,
                    'line': line
                })
        
        print(f"[+] Loaded {len(self.gadgets)} gadgets")
    
    def search_gadgets(self, patterns, is_regex=False):
        """Search for gadgets matching the given patterns"""
        matching = []
        
        if isinstance(patterns, str):
            patterns = [patterns]
        
        for pattern in patterns:
            if is_regex:
                # Pattern is already a regex, use as-is
                regex_pattern = pattern
            else:
                # Convert ropper-style pattern to regex
                regex_pattern = pattern
                
                # Escape special regex characters first (except *, ?, [, ])
                regex_pattern = regex_pattern.replace('(', r'\(').replace(')', r'\)')
                regex_pattern = regex_pattern.replace('+', r'\+')
                
                # Replace ??? with a pattern that matches registers, addresses, or values
                # Including brackets, commas, numbers, etc.
                regex_pattern = regex_pattern.replace('???', r'[^\;]+')
                
                # Replace e?? or r?? with register patterns
                regex_pattern = regex_pattern.replace('e??', r'e[a-z]{2}')
                regex_pattern = regex_pattern.replace('r??', r'r[a-z0-9]{2}')
                
                # Allow flexible whitespace around commas and other operators
                regex_pattern = regex_pattern.replace(',', r'\s*,?\s*')
                regex_pattern = regex_pattern.replace(' ', r'\s+')
                
                # Make semicolons flexible with optional whitespace
                regex_pattern = regex_pattern.replace(';', r'\s*;\s*')
                
                # Handle .* properly - make it non-greedy
                regex_pattern = regex_pattern.replace('.*', r'.*?')
            
            try:
                compiled = re.compile(regex_pattern, re.IGNORECASE)
            except re.error as e:
                print(f"[!] Invalid pattern '{pattern}': {e}")
                continue
            
            for gadget in self.gadgets:
                if compiled.search(gadget['instructions']):
                    matching.append(gadget)
        
        return matching
    
    def categorize_all(self):
        """Categorize all gadgets"""
        reg_prefix = "e" if self.arch == "x86" else "r"
        
        print(f"[+] Categorizing gadgets...")
        
        # Write-what-where (mov to memory address) - use raw regex
        patterns = [r"mov\s+(byte\s+|word\s+|dword\s+)?\["]
        self.categories['write-what-where'] = self.search_gadgets(patterns, is_regex=True)
        
        # Pointer dereference (mov from memory address) - use raw regex
        patterns = [r"mov\s+\w+,\s+(\[|dword\s+\[|byte\s+\[|word\s+\[)"]
        self.categories['pointer-deref'] = self.search_gadgets(patterns, is_regex=True)
        
        # Swap register
        patterns = ["mov ???, ???", "xchg ???, ???", "push ???.*pop ???"]
        self.categories['swap-register'] = self.search_gadgets(patterns)
        
        # Increment
        patterns = ["inc ???"]
        self.categories['increment'] = self.search_gadgets(patterns)
        
        # Decrement
        patterns = ["dec ???"]
        self.categories['decrement'] = self.search_gadgets(patterns)
        
        # Add
        patterns = [f"add ???, {reg_prefix}??"]
        self.categories['add'] = self.search_gadgets(patterns)
        
        # Subtract
        patterns = [f"sub ???, {reg_prefix}??"]
        self.categories['subtract'] = self.search_gadgets(patterns)
        
        # Negate
        patterns = [f"neg {reg_prefix}??"]
        self.categories['negate'] = self.search_gadgets(patterns)
        
        # XOR
        patterns = [f"xor {reg_prefix}??, 0x"]
        self.categories['xor'] = self.search_gadgets(patterns)
        
        # Push
        patterns = [f"push {reg_prefix}??"]
        self.categories['push'] = self.search_gadgets(patterns)
        
        # Pushad
        patterns = ["pushad", "pusha"]
        self.categories['pushad'] = self.search_gadgets(patterns)
        
        # Pop
        patterns = [f"pop {reg_prefix}??"]
        self.categories['pop'] = self.search_gadgets(patterns)
        
        # Push-pop
        patterns = [f"push {reg_prefix}??.*pop {reg_prefix}??"]
        self.categories['push-pop'] = self.search_gadgets(patterns)
        
        # Zeroize
        zeroize_patterns = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            zeroize_patterns.append(f"xor {reg}, {reg}")
            zeroize_patterns.append(f"sub {reg}, {reg}")
            zeroize_patterns.append(f"lea {reg}, 0")
            zeroize_patterns.append(f"mov {reg}, 0")
            zeroize_patterns.append(f"and {reg}, 0")
        self.categories['zeroize'] = self.search_gadgets(zeroize_patterns)
        
        # EIP to ESP
        eip_to_esp = [
            f"jmp {reg_prefix}sp",
            "leave",
            f"mov {reg_prefix}sp, ???",
            f"call {reg_prefix}sp",
        ]
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            eip_to_esp.append(f"xchg {reg_prefix}sp, {reg}.*jmp {reg}")
            eip_to_esp.append(f"xchg {reg_prefix}sp, {reg}.*call {reg}")
        self.categories['eip-to-esp'] = self.search_gadgets(eip_to_esp)
    
    def save_categories(self):
        """Save each category to a separate file"""
        print(f"[+] Writing categorized gadgets to {self.output_dir}")
        
        # Filter out large ret sizes
        gadget_filter = re.compile(r'ret 0x[0-9a-fA-F]{3,};')
        
        for category, gadgets in self.categories.items():
            output_file = self.output_dir / f"{category}.txt"
            
            # Remove duplicates and filter
            seen = set()
            filtered = []
            for gadget in gadgets:
                if gadget['line'] in seen:
                    continue
                if gadget_filter.search(gadget['instructions']):
                    continue
                seen.add(gadget['line'])
                filtered.append(gadget)
            
            with open(output_file, 'w') as f:
                f.write(f"# {category.upper()} GADGETS\n")
                f.write(f"# Total: {len(filtered)}\n\n")
                for gadget in filtered:
                    f.write(f"{gadget['line']}\n")
            
            print(f"  [{len(filtered):4d}] {category}")
        
        # Also create an all-in-one file
        all_file = self.output_dir / "all-categorized.txt"
        with open(all_file, 'w') as f:
            for category, gadgets in self.categories.items():
                f.write(f"\n{'='*70}\n")
                f.write(f"# {category.upper()} GADGETS\n")
                f.write(f"{'='*70}\n\n")
                
                seen = set()
                for gadget in gadgets:
                    if gadget['line'] in seen:
                        continue
                    if gadget_filter.search(gadget['instructions']):
                        continue
                    seen.add(gadget['line'])
                    f.write(f"{gadget['line']}\n")
        
        print(f"\n[+] All categories also written to: {all_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Categorize gadgets from rp++ output into separate files"
    )
    
    parser.add_argument(
        "-f",
        "--file",
        help="input file containing rp++ output (e.g., raw-rp-unique.txt)",
        required=True,
    )
    parser.add_argument(
        "-a",
        "--arch",
        choices=["x86", "x86_64"],
        help="architecture (default: x86)",
        default="x86",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        help="output directory for categorized files (default: categorized-gadgets)",
        default="categorized-gadgets",
    )
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"[!] Error: File not found: {args.file}")
        sys.exit(1)
    
    categorizer = GadgetCategorizer(args.file, args.arch, args.output_dir)
    categorizer.categorize_all()
    categorizer.save_categories()
    
    print(f"\n[+] Done! Check the {args.output_dir} directory for results.")
    print(f"\n[*] Usage tip:")
    print(f"    To search for specific patterns in a category:")
    print(f"    grep -i 'pattern' {args.output_dir}/category.txt")
    print(f"\n    To find clean gadgets (minimal instructions):")
    print(f"    awk '{{print length, $0}}' {args.output_dir}/category.txt | sort -n | head -20")


if __name__ == "__main__":
    main()
