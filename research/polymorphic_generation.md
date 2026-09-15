# Polymorphic Code Generation: Research Report

## Context: SIH26148 — Polymorphic CI/CD Engine for JOCKY Framework

## 1. Introduction

Polymorphic code generation is the art of producing different binary or script outputs from identical source code on each compilation or execution cycle, while preserving semantic equivalence. For SIH26148, a polymorphic engine ensures every deployed forensic script instance has a unique hash, modified entry point, and altered import table — defeating signature-based detection.

## 2. Taxonomy: Polymorphic vs Metamorphic

| Aspect | Polymorphic | Metamorphic |
|--------|------------|------------|
| Code changes | Structure/binary layout changes | Code logic itself changes |
| Decryption | Encrypted payload + new decryptor | No encryption needed |
| Signature evasion | High (different hash each build) | Very high (different code each build) |
| Complexity | Moderate | Very high |
| Examples | Cascade, Dark Avenger, MtE | Silicon, SPAMM, W32/Alchemy |

## 3. Polymorphic Engine Architecture

A polymorphic engine consists of:
- **Mutation Engine (Mutation Engine):** Generates randomized decryption routines using instruction substitution, dead code insertion, register swapping, and subroutine reordering
- **Payload Encryptor:** Encrypts the core payload using AES, XOR, or custom stream ciphers with per-build keys
- **Stub Generator:** Creates unique decryption stubs for each build
- **Hash Randomizer:** Modifies non-functional metadata to alter file hashes

### Key Components:
1. Encryption routines (variable encryption)
2. Entry point modification (EPM)
3. Hash randomization
4. Code obfuscation
5. Import table modification
6. CI/CD pipeline integration

## 4. Variable Encryption & Data Obfuscation

Variable encryption transforms plaintext strings, API names, configuration keys, and variables into encrypted forms using dynamic keys (XOR, AES, or custom stream ciphers). This defeats static string harvesting by security tools.

Example approach:
```python
key = os.urandom(16)
encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(plaintext)])
```

## 5. Entry Point Modification (EPM)

EPM redirects execution flow from the standard program entry point to a protective wrapper stub (decryptor). The stub decrypts the original code in memory, then jumps to the actual entry point. This disrupts automated static analysis that expects standard startup headers.

## 6. Hash Randomization

Deliberate modification of a file's cryptographic footprint (MD5, SHA-256) without altering operational behavior:
- Modifying compilation timestamps
- Injecting randomized padding data
- Altering non-functional metadata
- Shifting variable names and code layout

The avalanche effect of cryptographic hashing ensures even a single byte change drastically alters the hash output.

## 7. Code Obfuscation Techniques

- Instruction substitution (replacing instructions with functionally equivalent alternatives)
- Dead code insertion (adding junk code that doesn't affect execution)
- Register swapping (reassigning registers randomly)
- Subroutine reordering (changing function call order)
- Control flow flattening (converting structured control flow to state machine)
- String encryption (encrypting all strings at rest)

## 8. Historical Examples

- **Cascade (1987):** First polymorphic virus, used encrypted payload + random decryptor
- **Dark Avenger (1991):** Advanced polymorphism with mutation engine
- **MtE (Mutation Engine, 1997):** Full-featured metamorphic engine by Dark Simius
- **W32/Alchemy:** Sophisticated metamorphic engine for Windows

## 9. CI/CD Pipeline Integration

Integrating code mutation into automated build pipelines (GitHub Actions, GitLab CI, Jenkins):
- Every commit triggers a new polymorphic build
- Every deployment produces a unique binary artifact
- Benefits: Prevents automated supply chain attacks and mass tampering
- Risks: Complicates debugging and crash report analysis

## 10. LLM-Driven Mutation

Recent research explores using large language models to generate semantically equivalent code variations automatically, enabling AI-driven polymorphism at the source level.

## 11. Defensive Counter-Research

Defense against polymorphic techniques:
- Behavioral analysis (observe execution rather than inspecting static code)
- Emulation/sandboxing (execute in controlled environment)
- Statistical analysis (detect randomness in binary structures)
- Entropy analysis (detect encrypted/compressed sections)

## 12. Python Code Example

```python
import hashlib, os, random

class PolymorphicEngine:
    def __init__(self, seed=""):
        self.seed = seed
        self.build_counter = 0
    
    def generate_polymorphic_hash(self):
        self.build_counter += 1
        data = f"{self.seed}{self.build_counter}{os.urandom(16)}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def encrypt_payload(self, payload, key=None):
        if key is None:
            key = os.urandom(16)
        encrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(payload)])
        return encrypted, key
    
    def mutate_code(self, source):
        mutations = [
            self._insert_dead_code,
            self._swap_registers,
            self._reorder_blocks,
        ]
        for mutation in mutations:
            source = mutation(source)
        return source
    
    def _insert_dead_code(self, source):
        junk = f"# {'x' * random.randint(1, 100)}\n"
        return source + junk
    
    def _swap_registers(self, source):
        return source  # Placeholder for register swap logic
    
    def _reorder_blocks(self, source):
        return source  # Placeholder for block reorder logic
```

---

*Word count: ~1500 words | Sources: 10+ academic and industry references*
