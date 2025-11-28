# 🧠 Secure Memory Allocator

> *"A custom C memory management implementation designed to detect and prevent Buffer Overflow vulnerabilities and Heap Corruption."*

[![Language](https://img.shields.io/badge/Language-C-blue?style=for-the-badge&logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Security](https://img.shields.io/badge/Focus-Memory_Safety-red?style=for-the-badge&logo=security)](https://github.com/Thepimen)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()

---

## 📖 Project Overview

In systems programming, manual memory management is a common source of critical vulnerabilities. This project implements a **Custom Memory Allocator** that replaces standard `malloc` and `free` functions with secure versions (`secure_malloc` and `secure_free`).

The goal is to demonstrate how **Buffer Overflow** and **Heap Corruption** attacks can be mitigated using **Canaries** and runtime metadata validation.

---

## ⚙️ Technical Architecture

The allocator manages a static memory block (`my_heap`) and uses a linked list to track free and allocated blocks.

### Implemented Security Features:

1.  **Metadata Integrity Protection:**
    * Each memory block has a `Block` header containing metadata (size, status, pointers).
    * A **"Magic Canary"** (`0xDEADBEEF`) is inserted at the start of the metadata. If this value changes, it indicates that an overflow has corrupted the internal heap structure.

2.  **Buffer Overflow Detection:**
    * Upon allocation, a second **Canary** is written right after the user's requested space (in the "footer").
    * When freeing memory (`secure_free`), the system verifies if this canary is still intact. If it has been overwritten, the system detects the attack and aborts execution.

3.  **Allocation Algorithm:**
    * Uses **First-Fit** to find the first free block with sufficient space.
    * Implements **Block Splitting** to optimize memory usage if the found block is significantly larger than requested.

---

## 💻 Code Analysis

### Block Structure
```c
typedef struct Block {
    size_t size;            // Usable size of the block
    int is_free;            // Status flag
    uint32_t canary_start;  // 🛡️ Metadata protection Canary
    struct Block *next;     // Pointer to the next block
} Block;
