# Jasmin for ACC

[Jasmin](https://github.com/jasmin-lang/jasmin) can compile to ACC code.
`jasmin_library` in [rules/jasmin.bzl](../../../rules/jasmin.bzl) compiles a Jasmin source and assembles it into an `acc_library`.
The compiler is built by Nix, which must be on `PATH`.

[mul256.jazz](mul256.jazz) is the Jasmin counterpart of [mul256.s](../code-snippets/mul256.s).
To compile and test it:

```sh
./bazelisk.sh test //sw/acc/jasmin:mul256_test
```
