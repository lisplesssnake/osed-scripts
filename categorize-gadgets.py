#!/usr/bin/env python3
import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict


class GadgetCategorizer:
    def __init__(self, input_file, arch, output_dir, verbose=False, bad_bytes=None):
        self.input_file = input_file
        self.arch = arch
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose_mode = verbose
        self.bad_bytes = self.parse_bad_bytes(bad_bytes) if bad_bytes else []
        self.gadgets = []
        self.categories = defaultdict(list)
        self.bad_instructions = [
            'begin', 'int', 'call', 'jmp'
        ]
        # if you leave out 'leave', you miss eip to esp gadgets like:
        # 0x50506857  # leave; ret;
        # so i'll add it back
        # Note: 'call' is handled separately in is_bad_gadget()
        self.load_gadgets()
    
    def info(self, message):
        """Print info message in green - always displayed"""
        print(f"\033[92m{message}\033[0m")
    
    def debug(self, message):
        """Print debug message in cyan - only displayed in verbose mode"""
        if self.verbose_mode:
            print(f"\033[96m{message}\033[0m")

    def warning(self, message):
        """Print warning message"""
        print(f"\033[95m{message}\033[0m")
    
    def parse_bad_bytes(self, bad_bytes_str):
        """Parse bad bytes string like '00 0a 0d' into a list"""
        if not bad_bytes_str:
            return []
        # Remove any commas and split by whitespace
        bad_bytes_str = bad_bytes_str.replace(',', ' ')
        bytes_list = [b.strip().lower() for b in bad_bytes_str.split() if b.strip()]
        return bytes_list
    
    def has_bad_byte(self, address):
        """Check if an address contains any bad bytes"""
        if not self.bad_bytes:
            return False
        
        # Remove 0x prefix if present
        addr = address.lower().replace('0x', '')
        
        # Check each bad byte
        for bad_byte in self.bad_bytes:
            # Pad to 2 digits if needed (e.g., '0' -> '00')
            bad_byte = bad_byte.zfill(2)
            # Check if this byte appears in the address
            # We need to check byte by byte (every 2 hex chars)
            for i in range(0, len(addr), 2):
                if i + 2 <= len(addr):
                    addr_byte = addr[i:i+2]
                    if addr_byte == bad_byte:
                        return True
        return False

    def is_bad_gadget(self, line):
        """Check if a gadget line contains bad instructions"""
        
        # Check for call to absolute memory address (bad)
        # e.g., "call [0x5054A03C]" is bad
        # but "call eax" or "call [ecx+0x04]" is fine
        if re.search(r'\bcall\s+\[0x[0-9a-fA-F]+\]', line, re.IGNORECASE):
            return True
        
        # Check for retn with value > 0x200
        retn_match = re.search(r'\bretn?\s+0x([0-9a-fA-F]+)', line, re.IGNORECASE)
        if retn_match:
            retn_value = int(retn_match.group(1), 16)
            if retn_value > 0x200:
                return True
        
        for bad in self.bad_instructions:
            # Use word boundaries to match only complete instruction names
            pattern = r'\b' + re.escape(bad) + r'\b'
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False
    
    def load_gadgets(self):
        """Load gadgets from rp++ output file"""
        self.info(f"[+] Loading gadgets from {self.input_file}")
        
        if self.bad_bytes:
            self.info(f"[+] Bad bytes filter enabled: {' '.join(self.bad_bytes).upper()}")

        bad_gadgets_count = 0
        bad_bytes_count = 0
        
        with open(self.input_file, 'r') as f:
            for i, line in enumerate(f):
                line = line.strip().rsplit(";", 1)[0]
                if i == 0 or i == 1:
                    self.debug(f"[+] rp++: {line}")

                if "A total of" in line:
                    self.debug(f"[+] rp++: {line}")
                if "unique gadgets found" in line:
                    self.debug(f"[+] rp++: {line}")
                if "gadgets have been filtered because of bad-bytes" in line:
                    self.debug(f"[+] rp++: {line}")
                
                if not line.startswith('0x'):
                    continue
                
                # Parse: "0x10001234: instruction; instruction; ret;"
                parts = line.split(':', 1)
                
                if len(parts) != 2:
                    continue
                
                address = parts[0].strip()
                instructions = parts[1].strip()

                # Check for bad bytes in address
                if self.has_bad_byte(address):
                    bad_bytes_count += 1
                    continue

                if self.is_bad_gadget(instructions):
                    bad_gadgets_count += 1
                    continue

                self.gadgets.append({
                    'address': address,
                    'instructions': instructions,
                    'line': line
                })
        
        self.info(f"[+] Loaded {len(self.gadgets)} gadgets")
        if bad_bytes_count > 0:
            self.info(f"[+] Filtered out {bad_bytes_count} gadgets with bad bytes in address")
        self.info(f"[+] Skipped {bad_gadgets_count} bad gadgets because they used {self.bad_instructions} or a bad call")
    
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
                self.info(f"[!] Invalid pattern '{pattern}': {e}")
                continue
            
            for gadget in self.gadgets:
                if compiled.search(gadget['instructions']):
                    matching.append(gadget)
        
        return matching
    
    def save_filtered_copy(self):
        """Save a copy of the input file with bad gadgets removed"""
        input_path = Path(self.input_file)
        output_file = self.output_dir / f"{input_path.stem}-filtered{input_path.suffix}"
        
        self.debug(f"[+] Writing filtered copy to {output_file}")
        
        with open(output_file, 'w') as f:
            for gadget in self.gadgets:
                f.write(f"{gadget['line']}\n")
        
        self.info(f"[+] Filtered copy contains {len(self.gadgets)} gadgets")
    
    def categorize_all(self):
        """Categorize all gadgets"""
        reg_prefix = "e" if self.arch == "x86" else "r"
        
        self.debug(f"[+] Categorizing gadgets...")
        
        # Write-what-where (mov to memory address) - use raw regex
        patterns = [r"mov\s+(byte\s+|word\s+|dword\s+)?\["]
        self.categories['01-write-what-where'] = self.search_gadgets(patterns, is_regex=True)
        
        # Pointer dereference (mov from memory address) - use raw regex
        patterns = [r"mov\s+\w+,\s+(\[|dword\s+\[|byte\s+\[|word\s+\[)"]
        self.categories['02-pointer-deref'] = self.search_gadgets(patterns, is_regex=True)
        
        # Swap register
        patterns = ["mov ???, ???", "xchg ???, ???", "push ???.*pop ???"]
        self.categories['03-swap-register'] = self.search_gadgets(patterns)
        
        # Increment
        patterns = ["inc ???"]
        self.categories['04-increment'] = self.search_gadgets(patterns)
        
        # Decrement
        patterns = ["dec ???"]
        self.categories['05-decrement'] = self.search_gadgets(patterns)
        
        # Add
        patterns = [f"add ???, {reg_prefix}??"]
        self.categories['06-add'] = self.search_gadgets(patterns)
        
        # Subtract
        patterns = [f"sub ???, {reg_prefix}??"]
        self.categories['07-subtract'] = self.search_gadgets(patterns)
        
        # Negate
        patterns = [f"neg {reg_prefix}??"]
        self.categories['08-negate'] = self.search_gadgets(patterns)
        
        # XOR
        patterns = [f"xor {reg_prefix}??, 0x"]
        self.categories['09-xor'] = self.search_gadgets(patterns)
        
        # Push
        patterns = [f"push {reg_prefix}??"]
        self.categories['10-push'] = self.search_gadgets(patterns)
        
        # Pushad
        patterns = ["pushad", "pusha"]
        self.categories['11-pushad'] = self.search_gadgets(patterns)
        
        # Pop
        patterns = [f"pop {reg_prefix}??"]
        self.categories['12-pop'] = self.search_gadgets(patterns)
        
        # Push-pop
        patterns = [f"push {reg_prefix}??.*pop {reg_prefix}??"]
        self.categories['13-push-pop'] = self.search_gadgets(patterns)
        
        # Zeroize
        zeroize_patterns = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            zeroize_patterns.append(f"xor {reg}, {reg}")
            zeroize_patterns.append(f"sub {reg}, {reg}")
            # Match exactly 0, 0x0, or 0x00 etc, not addresses like 0x10093864
            zeroize_patterns.append(f"lea {reg}, 0x0+\\b")
            zeroize_patterns.append(f"mov {reg}, 0x0+\\b")
            zeroize_patterns.append(f"and {reg}, 0x0+\\b")
        self.categories['14-zeroize'] = self.search_gadgets(zeroize_patterns, is_regex=True)
        
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
            eip_to_esp.append(f"xchg {reg_prefix}sp, {reg}")
        self.categories['15-eip-to-esp'] = self.search_gadgets(eip_to_esp)

        # copy ESP
        copy_esp = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            copy_esp.append(f"mov {reg}, {reg_prefix}sp")
            copy_esp.append(f"push {reg_prefix}sp ; pop {reg}")
            copy_esp.append(f"push {reg_prefix}sp .* pop {reg}")
            # copy_esp.append(f"xchg {reg_prefix}sp, {reg}")
            # copy_esp.append(f"xchg {reg}, {reg_prefix}sp")
            
        self.categories['16-copy-esp'] = self.search_gadgets(copy_esp)
        
    
    def save_categories(self):
        """Save each category to a separate file"""
        self.debug(f"[+] Writing categorized gadgets to {self.output_dir}")
        
        # Create subdirectories for regular and clean categories
        regular_dir = self.output_dir / "regular"
        clean_dir = self.output_dir / "clean"
        regular_dir.mkdir(parents=True, exist_ok=True)
        clean_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter out large ret sizes
        gadget_filter = re.compile(r'ret 0x[0-9a-fA-F]{3,};')
        
        for category, gadgets in self.categories.items():
            # Determine which directory to use
            if category.endswith('-clean'):
                output_file = clean_dir / f"{category.replace('-clean', '')}.txt"
            else:
                output_file = regular_dir / f"{category}.txt"
            
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
            
            self.debug(f"  [{len(filtered):4d}] {category}")
        
        # Also create all-in-one files in each subdirectory
        all_file = regular_dir / "00-all-categorized.txt"
        all_file_clean = clean_dir / "00-all-categorized.txt"
        
        with open(all_file, 'w') as f:
            for category, gadgets in self.categories.items():
                if category.endswith('-clean'):
                    continue
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
        
        with open(all_file_clean, 'w') as f:
            for category, gadgets in self.categories.items():
                if not category.endswith('-clean'):
                    continue
                f.write(f"\n{'='*70}\n")
                f.write(f"# {category.upper().replace('-CLEAN', '')} GADGETS\n")
                f.write(f"{'='*70}\n\n")
                
                seen = set()
                for gadget in gadgets:
                    if gadget['line'] in seen:
                        continue
                    if gadget_filter.search(gadget['instructions']):
                        continue
                    seen.add(gadget['line'])
                    f.write(f"{gadget['line']}\n")
        
        self.debug(f"[+] Regular categories written to: {regular_dir}")
        self.debug(f"[+] Clean categories written to: {clean_dir}")
    
    def categorize_clean(self):
        """Categorize only single-instruction gadgets (and some 2-instruction for specific categories)"""
        self.debug(f"[+] Categorizing clean (single-instruction) gadgets...")
        
        # Filter to only single instruction gadgets
        single_instruction_gadgets = []
        two_instruction_gadgets = []
        for gadget in self.gadgets:
            # Split by semicolon and count instructions
            # Format is "instruction; ret; (5 found)"
            
            parts = [p.strip() for p in gadget['instructions'].split(';') if p.strip()]
                
            # Should have exactly 2 parts: the instruction and ret
            if len(parts) == 2 and parts[1].startswith('ret'):
                single_instruction_gadgets.append(gadget)
            # Should have exactly 3 parts: instruction1; instruction2; ret
            elif len(parts) == 3 and parts[2].startswith('ret'):
                two_instruction_gadgets.append(gadget)
        
        self.info(f"[+] Found {len(single_instruction_gadgets)} single-instruction gadgets")
        self.info(f"[+] Found {len(two_instruction_gadgets)} two-instruction gadgets")
        
        # Temporarily use only single-instruction gadgets for categorization
        original_gadgets = self.gadgets
        self.gadgets = single_instruction_gadgets
        
        reg_prefix = "e" if self.arch == "x86" else "r"
        
        # Write-what-where
        patterns = [r"mov\s+(byte\s+|word\s+|dword\s+)?\["]
        self.categories['01-write-what-where-clean'] = self.search_gadgets(patterns, is_regex=True)
        
        # Pointer dereference
        patterns = [r"mov\s+\w+,\s+(\[|dword\s+\[|byte\s+\[|word\s+\[)"]
        self.categories['02-pointer-deref-clean'] = self.search_gadgets(patterns, is_regex=True)
        
        # Swap register (allow 2-instruction for push/pop patterns)
        patterns = ["mov ???, ???", "xchg ???, ???"]
        self.categories['03-swap-register-clean'] = self.search_gadgets(patterns)
        # Add push/pop from 2-instruction gadgets
        self.gadgets = two_instruction_gadgets
        patterns = ["push ???.*pop ???"]
        self.categories['03-swap-register-clean'].extend(self.search_gadgets(patterns))
        self.gadgets = single_instruction_gadgets
        
        # Increment
        patterns = ["inc ???"]
        self.categories['04-increment-clean'] = self.search_gadgets(patterns)
        
        # Decrement
        patterns = ["dec ???"]
        self.categories['05-decrement-clean'] = self.search_gadgets(patterns)
        
        # Add
        patterns = [f"add ???, {reg_prefix}??"]
        self.categories['06-add-clean'] = self.search_gadgets(patterns)
        
        # Subtract
        patterns = [f"sub ???, {reg_prefix}??"]
        self.categories['07-subtract-clean'] = self.search_gadgets(patterns)
        
        # Negate
        patterns = [f"neg {reg_prefix}??"]
        self.categories['08-negate-clean'] = self.search_gadgets(patterns)
        
        # XOR
        patterns = [f"xor {reg_prefix}??, 0x"]
        self.categories['09-xor-clean'] = self.search_gadgets(patterns)
        
        # Push
        patterns = [f"push {reg_prefix}??"]
        self.categories['10-push-clean'] = self.search_gadgets(patterns)
        
        # Pushad
        patterns = ["pushad", "pusha"]
        self.categories['11-pushad-clean'] = self.search_gadgets(patterns)
        
        # Pop
        patterns = [f"pop {reg_prefix}??"]
        self.categories['12-pop-clean'] = self.search_gadgets(patterns)
        
        # Zeroize
        zeroize_patterns = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            zeroize_patterns.append(f"xor {reg}, {reg}")
            zeroize_patterns.append(f"sub {reg}, {reg}")
            # Match exactly 0, 0x0, or 0x00 etc, not addresses like 0x10093864
            zeroize_patterns.append(f"lea {reg}, 0x0+\\b")
            zeroize_patterns.append(f"mov {reg}, 0x0+\\b")
            zeroize_patterns.append(f"and {reg}, 0x0+\\b")
        self.categories['14-zeroize-clean'] = self.search_gadgets(zeroize_patterns, is_regex=True)
        
        # EIP to ESP
        eip_to_esp = [
            f"jmp {reg_prefix}sp",
            f"call {reg_prefix}sp",    
        ]
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            eip_to_esp.append(f"xchg {reg_prefix}sp, {reg}")
            eip_to_esp.append(f"xchg {reg}, {reg_prefix}sp")
        
        self.categories['15-eip-to-esp-clean'] = self.search_gadgets(eip_to_esp)

        # copy ESP (allow 2-instruction for push/pop patterns)
        copy_esp = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            copy_esp.append(f"mov {reg}, {reg_prefix}sp")
            # copy_esp.append(f"xchg {reg_prefix}sp, {reg}")
            # copy_esp.append(f"xchg {reg}, {reg_prefix}sp")
        self.categories['16-copy-esp-clean'] = self.search_gadgets(copy_esp)
        # Add push esp; pop reg from 2-instruction gadgets
        self.gadgets = two_instruction_gadgets
        copy_esp_2instr = []
        for reg in [f"{reg_prefix}ax", f"{reg_prefix}bx", f"{reg_prefix}cx", 
                    f"{reg_prefix}dx", f"{reg_prefix}si", f"{reg_prefix}di"]:
            copy_esp_2instr.append(f"push {reg_prefix}sp.*pop {reg}")
        self.categories['16-copy-esp-clean'].extend(self.search_gadgets(copy_esp_2instr))
        self.gadgets = single_instruction_gadgets
        
        # Restore original gadgets
        self.gadgets = original_gadgets


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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose output",
    )
    parser.add_argument(
        "-b",
        "--bad-bytes",
        help="bad bytes to filter from gadget addresses (e.g., '00 0a 0d' or '00,0a,0d')",
        default=None,
    )
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"[!] Error: File not found: {args.file}")
        sys.exit(1)
    
    categorizer = GadgetCategorizer(args.file, args.arch, args.output_dir, args.verbose, args.bad_bytes)
    categorizer.save_filtered_copy()
    categorizer.categorize_all()
    categorizer.categorize_clean()  # only one instruction gadgets
    categorizer.save_categories()
    
    categorizer.info(f"\n[+] Done! Check the {args.output_dir} directory for results.")
    if args.verbose:
        print(f"\n[*] Usage tip:")
        print(f"    To search for specific patterns in a category:")
        print(f"    grep -i 'pattern' {args.output_dir}/regular/category.txt")
        print(f"    grep -i 'pattern' {args.output_dir}/clean/category.txt")
    categorizer.warning(f"!!!! DO NOT REMOVE BADCHARS WITH RP++ (BUGGY), LET THIS SCRIPT HANDLE IT!!!")
    

if __name__ == "__main__":
    main()
