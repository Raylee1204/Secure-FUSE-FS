# Secure-FUSE-FS: Encrypted In-Memory Filesystem

**Secure-FUSE-FS** is a lightweight, user-space filesystem implemented in C using the **FUSE (Filesystem in Userspace)** interface. It functions primarily as an in-memory filesystem but integrates **AES-256-CBC encryption** to ensure data confidentiality.

This project demonstrates the interception of Linux system calls (VFS layer) to implement transparent encryption and decryption mechanisms, a critical concept in secure storage systems and firmware security.

## 🚀 Key Features

* **Custom FUSE Implementation**: Handles standard filesystem operations including `mkdir`, `rmdir`, `mknod`, `write`, `read`, `open`, and `getattr`.
* **Transparent Encryption**:
    * Integrates **OpenSSL (EVP API)** for cryptographic operations.
    * Uses **AES-256-CBC** algorithm.
    * **Per-File Security**: Generates a unique 256-bit Key and 128-bit IV for every new file.
* **In-Memory Architecture**: Simulates inodes and data blocks using dynamic arrays in C, providing low-latency operations.
* **Shadow Storage verification**: While the mount point exposes cleartext data to authorized users, the encrypted binary blobs are verified by writing to a shadow directory (`/usr/src/test_tmp`) to prove physical data security.

## 🛠️ System Architecture

The filesystem operates by intercepting VFS calls and mapping them to internal memory structures.

1.  **Write Operation (`do_write`)**:
    * User writes data -> FUSE intercepts call.
    * Data is encrypted using the file's unique AES Key/IV.
    * Encrypted blob is stored in the memory buffer and flushed to shadow storage for persistence verification.
2.  **Read Operation (`do_read`)**:
    * User requests read -> FUSE intercepts call.
    * System retrieves encrypted blob from memory.
    * Data is decrypted on-the-fly and returned to the user buffer.

## 💻 Prerequisites

* **OS**: Linux (Ubuntu 20.04/22.04 recommended)
* **Libraries**:
    * `libfuse-dev` (FUSE development headers)
    * `libssl-dev` (OpenSSL development headers)
    * `gcc`, `make`

```bash
sudo apt-get update
sudo apt-get install fuse libfuse-dev libssl-dev gcc make
