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
python3 categorize-gadgets.py -f raw-rp-unique.txt -a x86 -o categorized-gadgets
```

## Output

The script creates separate files for each category:

- **write-what-where.txt** - `mov [mem], reg` gadgets for writing to memory
- **pointer-deref.txt** - `mov reg, [mem]` gadgets for reading from memory  
- **swap-register.txt** - `mov`, `xchg`, `push/pop` for moving data between registers
- **increment.txt** - `inc` gadgets
- **decrement.txt** - `dec` gadgets
- **add.txt** - `add` gadgets
- **subtract.txt** - `sub` gadgets
- **negate.txt** - `neg` gadgets
- **xor.txt** - `xor` with immediate values
- **push.txt** - `push` gadgets
- **pop.txt** - `pop` gadgets
- **push-pop.txt** - Combined push/pop gadgets
- **pushad.txt** - `pushad`/`pusha` gadgets
- **zeroize.txt** - Gadgets to zero out registers (`xor reg, reg`, etc.)
- **eip-to-esp.txt** - Stack pivot gadgets (`jmp esp`, `call esp`, `leave`, etc.)
- **all-categorized.txt** - All categories in one file

## Arguments

```cmd
-f, --file          Input file containing rp++ output (required)
-a, --arch          Architecture: x86 or x86_64 (default: x86)
-o, --output-dir    Output directory for categorized files (default: categorized-gadgets)
```

## Tips

### Find clean gadgets (fewest instructions)

```bash
awk '{print length, $0}' categorized-gadgets/pop.txt | sort -n | head -20
```

### Search for specific patterns

```bash
grep -i 'esp' categorized-gadgets/eip-to-esp.txt
grep -i 'edi.*esi' categorized-gadgets/pop.txt
```

### Count gadgets per category

```bash
wc -l categorized-gadgets/*.txt
```

## Example Workflow

```bash
# 1. Find gadgets with bad bytes filtered
rp-lin-x64 -f csftpav6.dll --bad-bytes "00 0a 0d" --unique -r5 > raw-gadgets.txt

# 2. Categorize them
python3 categorize-gadgets.py -f raw-gadgets.txt -o my-gadgets

# 3. Find clean pop-pop-ret gadgets
awk '{print length, $0}' my-gadgets/pop.txt | sort -n | grep -E 'pop.*pop.*ret' | head -10

# 4. Search for stack pivots
grep -i 'xchg.*esp' my-gadgets/eip-to-esp.txt
```

## Advantages Over the Old Approach

1. **Simpler** - No complex integration with multiple tools
2. **Transparent** - You control the rp++ command and see exactly what it finds
3. **Flexible** - Easy to modify patterns or add new categories
4. **Debuggable** - If something's wrong, you can inspect the raw rp++ output
5. **Reliable** - No dependencies on ropper's API or behavior

## Notes

- The script automatically filters out gadgets with large return offsets (`ret 0x???` where ??? > 255)
- Duplicate gadgets are removed within each category
- All gadgets are also saved in `all-categorized.txt` for reference
