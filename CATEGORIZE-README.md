# categorize-gadgets.py

A simple and efficient gadget categorizer that reads raw rp++ output and organizes gadgets into useful categories.

## Why This Approach?

Instead of trying to integrate rp++ with ropper or other tools, this script takes a simpler approach:

1. You manually run rp++ with your desired options (including bad bytes filtering)
2. This script reads the output and categorizes gadgets into separate files
3. Much easier to debug and understand what's happening

## Usage

### Step 1: Run rp++ and save output

```bash
# Example: Find gadgets excluding bad bytes 00 and 0a
rp-lin-x64 -f binary.dll --bad-bytes "00 0a" --unique > raw-rp-unique.txt
```

### Step 2: Categorize the gadgets

```bash
# Basic usage
python3 categorize-gadgets.py -f raw-rp-unique.txt -a x86 -o categorized-gadgets

# With verbose output for detailed progress
python3 categorize-gadgets.py -f raw-rp-unique.txt -a x86 -o categorized-gadgets -v
```

## Output

The script creates:

1. **Filtered copy** - `raw-rp-unique-filtered.txt` - Original file with bad gadgets removed
2. **Two subdirectories** with categorized gadgets:

### Regular Gadgets (`regular/`)

Multi-instruction gadgets organized by category:

- **01-write-what-where.txt** - `mov [mem], reg` gadgets for writing to memory
- **02-pointer-deref.txt** - `mov reg, [mem]` gadgets for reading from memory  
- **03-swap-register.txt** - `mov`, `xchg`, `push/pop` for moving data between registers
- **04-increment.txt** - `inc` gadgets
- **05-decrement.txt** - `dec` gadgets
- **06-add.txt** - `add` gadgets
- **07-subtract.txt** - `sub` gadgets
- **08-negate.txt** - `neg` gadgets
- **09-xor.txt** - `xor` with immediate values
- **10-push.txt** - `push` gadgets
- **11-pushad.txt** - `pushad`/`pusha` gadgets
- **12-pop.txt** - `pop` gadgets
- **13-push-pop.txt** - Combined push/pop gadgets
- **14-zeroize.txt** - Gadgets to zero out registers (`xor reg, reg`, etc.)
- **15-eip-to-esp.txt** - Stack pivot gadgets (`jmp esp`, `call esp`, `leave`, etc.)
- **00-all-categorized.txt** - All regular categories in one file

### Clean Gadgets (`clean/`)

Single-instruction gadgets only (instruction + ret) - same categories as above but cleaner

## Arguments

```cmd
-f, --file          Input file containing rp++ output (required)
-a, --arch          Architecture: x86 or x86_64 (default: x86)
-o, --output-dir    Output directory for categorized files (default: categorized-gadgets)
-v, --verbose       Enable verbose output with detailed progress (optional)
```

## Tips

### Find clean gadgets (single-instruction only)

```bash
# All clean gadgets are in the clean/ subdirectory
ls categorized-gadgets/clean/

# Find shortest gadgets in a category
awk '{print length, $0}' categorized-gadgets/clean/12-pop.txt | sort -n | head -20
```

### Search for specific patterns

```bash
# Search in regular gadgets
grep -i 'esp' categorized-gadgets/regular/15-eip-to-esp.txt

# Search in clean gadgets
grep -i 'eax' categorized-gadgets/clean/12-pop.txt

# Search across all regular categories
grep -r 'edi.*esi' categorized-gadgets/regular/
```

### Count gadgets per category

```bash
# Count regular gadgets
wc -l categorized-gadgets/regular/*.txt

# Count clean gadgets
wc -l categorized-gadgets/clean/*.txt

# Compare regular vs clean
echo "Regular:" && wc -l categorized-gadgets/regular/*.txt | tail -1
echo "Clean:" && wc -l categorized-gadgets/clean/*.txt | tail -1
```

## Example Workflow

```bash
# 1. Find gadgets with bad bytes filtered
rp-lin-x64 -f csftpav6.dll --bad-bytes "00 0a 0d" --unique -r5 > raw-gadgets.txt

# 2. Categorize them (verbose mode)
python3 categorize-gadgets.py -f raw-gadgets.txt -o my-gadgets -v

# 3. Check the filtered copy (bad gadgets removed)
wc -l my-gadgets/raw-gadgets-filtered.txt

# 4. Find clean pop gadgets (single instruction + ret)
cat my-gadgets/clean/12-pop.txt

# 5. Find multi-instruction pop-pop-ret sequences
awk '{print length, $0}' my-gadgets/regular/12-pop.txt | sort -n | grep -E 'pop.*pop.*ret' | head -10

# 6. Search for stack pivots
grep -i 'xchg.*esp' my-gadgets/regular/15-eip-to-esp.txt

# 7. Compare regular vs clean gadget counts
echo "Regular gadgets:" && wc -l my-gadgets/regular/*.txt | tail -1
echo "Clean gadgets:" && wc -l my-gadgets/clean/*.txt | tail -1
```

## Bad Gadget Filtering

The script automatically filters out gadgets containing:

- `int` - Interrupt instructions
- `retn` - Return with immediate (usually unwanted)
- `begin` - Invalid/malformed instructions
- `call [0x...]` - Calls to absolute memory addresses (but allows `call eax`, `call [eax+4]`, etc.)

## Notes

- Duplicate gadgets are removed within each category
- Clean gadgets contain only ONE instruction + ret (e.g., `pop eax; ret`)
- Regular gadgets can contain multiple instructions before ret
- All gadgets are also saved in `00-all-categorized.txt` within each subdirectory
- Use `-v` flag to see detailed progress including rp++ headers and category counts
