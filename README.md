# bn-seccomp

## Installation

Clone this repository in `~/.binaryninja/plugins` (or the equivalent for other operating systems).

## Usage

First, dump the filter in raw form with [seccomp-tools](https://github.com/david942j/seccomp-tools):

```
seccomp-tools dump -f raw ./your-binary >filter.bin
```

Then load `filter.bin` in binja
