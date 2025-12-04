# Tutorial 5: Extending Revizor

In this tutorial, we will switch gears: instead of using Revizor's existing components, we will extend Revizor by adding custom functionality to some of its core modules.

## Workflow

The general workflow for extending any part of Revizor is as follows:

- Subclass the exiting module or interface you want to extend. For a list of all interfaces, refer to the [Architecture Overview](../../internals/architecture/overview.md) document.
- Implement your custom logic by overwriting the necessary methods.
- Register your new class in the factory so that Revizor can access the new implementation. It will also enable the user to select the new implementation via a config file.
- Add new configuration options if your extension requires additional parameters.

## Changing Data Generation Algorithm

As our first example, we will modify the data (input) generation algorithm used by Revizor. By default, Revizor generates random input data for each test case. However, in some scenarios, it may be beneficial to generate inputs that contain extreme values (e.g., minimum or maximum integers) to test edge cases in the microarchitecture. We will implement this feature.

The data generation logic is defined by the `DataGenerator` interface, with its default implementation located in `rvzr/data_generator.py`. We will create a new subclass of `DataGenerator` that generates minimum or maximum integer values with a configurable probability.

Implement the new generation algorithm by overwriting the generation logic in the default `DataGenerator` class.

``` python
# rvzr/data_generator.py
class MinMaxIntGenerator(DataGenerator):
    """
    A variant of DataGenerator that generates minimum or maximum integer
    values with a configurable probability.
    """
    int_sizes: Final[List[int]] = [8, 16, 32, 64]

    def __init__(self, seed: int):
        super().__init__(seed)
        self._probability_of_max = CONF.input_gen_probability_of_minmax

    def _generate_one(self, state: int, n_actors: int) -> Tuple[InputData, int]:
        input_ = InputData(n_actors)
        input_.seed = state

        per_actor_data_size = input_.itemsize // 8

        rng = np.random.default_rng(seed=state)
        for i in range(n_actors):
            # generate random data
            data = rng.integers(
                self.max_input_value, size=per_actor_data_size, dtype=np.uint64)  # type: ignore

            # if the probability of max is 0, we're done
            if self._probability_of_max == 0:
                input_.set_actor_data(i, data)
                continue

            # otherwise, with a given probability, set some values to min or max int
            for val_id in range(per_actor_data_size):
                roll = rng.random()
                if roll > self._probability_of_max:
                    continue
                int_size = random.choice(self.int_sizes)
                int_sign = random.choice([True, False])
                value = (2 ** (int_size - 1))
                if not int_sign:
                    value = -value
                data[val_id] = np.uint64(value & 0xFFFFFFFFFFFFFFFF)

            input_.set_actor_data(i, data)

        return input_, state + 1
```

We now need to let Revizor know about the existence of this new class. This is achieved by via the factory module `rvzr/factory.py`:

``` python
# rvzr/factory.py
_DATA_GENERATORS: Dict[str, Type[data_generator.DataGenerator]] = {
    'random': data_generator.DataGenerator,
    'minmax': data_generator.MinMaxIntGenerator,  # <<<<<<<<<<<<<<<< ADDED LINE
}
```

Finally, our implementation used a new config option (`input_gen_probability_of_minmax`) to control the probability of generating extreme values. We need to register this new option in the configuration module `rvzr/config.py`:

``` python
# rvzr/config.py
class Config:
    ...
    input_gen_probability_of_minmax: float = 0.5  # <<<<<<<<<<<<<<<< ADDED LINE
```

That's it. That's all it takes to change the data generation algorithm in Revizor.

Now, let's test the implementation:

``` yaml
# config.yaml
data_generator: minmax
input_gen_probability_of_minmax: 0.7
```

Run Revizor with the new configuration:

``` shell
./revizor.py generate -s base.json -c config.yaml -w ./ -n 1 -i 1
```

See that the new generator was applied:

```
$ hexdump -C ./tc0/input0.bin| head -10
00000000  80 ff ff ff ff ff ff ff  00 00 00 00 00 00 00 80  |................|
00000010  00 80 ff ff ff ff ff ff  2a 35 00 00 00 00 00 00  |........*5......|
00000020  80 00 00 00 00 00 00 00  00 80 00 00 00 00 00 00  |................|
00000030  c4 83 00 00 00 00 00 00  37 26 00 00 00 00 00 00  |........7&......|
00000040  36 d5 00 00 00 00 00 00  00 80 ff ff ff ff ff ff  |6...............|
00000050  41 27 00 00 00 00 00 00  00 80 00 00 00 00 00 00  |A'..............|
00000060  32 69 00 00 00 00 00 00  64 b0 00 00 00 00 00 00  |2i......d.......|
00000070  00 80 ff ff ff ff ff ff  7c d7 00 00 00 00 00 00  |........|.......|
00000080  00 00 00 00 00 00 00 80  00 80 00 00 00 00 00 00  |................|
00000090  31 86 00 00 00 00 00 00  f9 f4 00 00 00 00 00 00  |1...............|
```

Success! We can see large and small integer values in the generated input data (`ff ff ff ...`),
meaning that our new data generator is working as expected.

## Adding a Code Generation Pass

We will now explore the other part of the test case generation pipeline - generation of test case programs (code). In this example, we will add a new code generation pass that replaces all registers in the test case with a fixed register (`RAX`).

!!! note
    Frankly, it is not a very useful generation pass, but it serves the purpose of demonstration. The same principles apply to more complex generation passes.

We will follow the same steps as before. The code pass interface is located in `rvzr/code_generator.py` as the `Pass` class. We will create a new subclass of it, and, since we are creating an ISA-specific pass, we will place it into `rvzr/arch/x86/generator.py`.

``` python
# rvzr/arch/x86/generator.py
class _X86RaxPass(Pass):
    """
    Demonstration-only pass that replaces all register operands with RAX.
    """

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        for bb in test_case.iter_basic_blocks():
            for node in bb.iter_nodes():
                inst = node.instruction
                for op in inst.operands:
                    if isinstance(op, RegisterOp):
                        op.value = "rax"
```

Register the new class with the generator:

``` python
# rvzr/arch/x86/generator.py
class X86Generator(CodeGenerator):
    ...
        self._passes = [
            _X86PatchUndefinedFlagsPass(self._instruction_set, self),
            _X86SandboxPass(self._target_desc, self._faults),
            _X86PatchUndefinedResultPass(),
            _X86RaxPass(),  # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ADDED LINE
        ]
```

That's it. Now, let's test our new code generation pass by running Revizor again:

```
./revizor.py generate -w . -n 1 -i 1 -s base.json
```

Check the generated program:

```
$ cat tc0/program.asm | head -10

.intel_syntax noprefix
.section .data.main
.function_0:
.bb_0.0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rax, 0b1111111111000 # instrumentation
lock add byte ptr [r14 + rdi], rax
cmp rax, 106
or rax, 0b1000000000000000000000000000000 # instrumentation
bsr rax, rax
```

As we can see, all register operands have been replaced with `RAX`, confirming that our new code generation pass is functioning correctly.


