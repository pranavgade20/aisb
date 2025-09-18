# Pickle MD5 Collision Generator

This project demonstrates how to create MD5 hash collisions between pickle files using precomputed collision blocks. The technique combines:
- Reusable MD5 collision blocks computed using Marc Stevens's [hashclash](https://github.com/cr-marcstevens/hashclash)
- File format tricks inspired by Ange Albertini's ([collisions](https://github.com/corkami/collisions))

Crucially, once the collision blocks have been precomputed (the hard part), they can be used to create a hash collision between any two pickle files. These files can have different lengths, store different data types, etc. No new computation occurs - only file manipulation.

Limitations:
- the collision blocks were precomputed under the assumption that the pickle files are in protocol #4 (for no special reason other than it is currently the most common protocol). When creating a collision between pickle files of a newer protocol, things might not work if there are some newer opcodes that are not supported in version #4. But if all the opcodes used were already introduced in previous versions, everything should be fine.
- the colliding pickles expose both of the original files. This means that a careful observer would be able to look at the hexdump of this pickle and realise that something is wrong. But of course almost no one ever does that in practice, as long as the file is loaded correctly by the parser.
- the stacks of the final colliding pickles are not empty, so using the pickletools disassembler `python -m pickletools file` will raise `ValueError`. Again, not many people would check the disassembly, only whether the file loads correctly (and it does).

Detailed writeup to follow soon.

## Prerequisites

The project requires two precomputed collision block files:
- `collision_blocks1.bin`
- `collision_blocks2.bin`

These files are specific to `prefix_16_pickle.bin` and **must not be modified** in any way. They contain carefully crafted 128-byte blocks that produce identical MD5 hashes.

## Usage

The main script `make_pickle_collision.py` accepts the following arguments:

```bash
# Required arguments
-f1, --file1         Path to first input pickle file
-f2, --file2         Path to second input pickle file

# Optional arguments with defaults
-c1, --collision_blocks1    Path to first collision block (default: collision_blocks1.bin)
-c2, --collision_blocks2    Path to second collision block (default: collision_blocks2.bin)
-o1, --output1             Path to first output pickle file (default: colliding_pickle1.pkl)
-o2, --output2             Path to second output pickle file (default: colliding_pickle2.pkl)
```

## Examples

You can find example pickle files in the `examples` folder. To replicate them:

```bash
# Example 1
./make_pickle_collision.py \
    -f1 examples/example1_in1.pkl \
    -f2 examples/example1_in2.pkl \
    -o1 examples/example1_out1.pkl \
    -o2 examples/example1_out2.pkl
```
and similarly for others.

## Verification

To verify the collisions, you can:

1. Check the MD5 hashes:
```bash
md5sum file1.pkl file2.pkl
```

2. Deserialize and view the pickle contents:
```bash
python -m pickle file1.pkl file2.pkl
```

The output files should have identical MD5 hashes but different contents when deserialized.