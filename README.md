# Security Enhancement of Mini-AES with Key-Dependent Dynamic S-Box

## Overview
This research project focuses on improving the security of the **Mini-AES** block cipher. By replacing the traditional static S-Box with a **Dynamic S-Box** that changes based on the encryption key, we significantly enhance the cipher's resistance to cryptanalysis.

## Technical Contributions
- **Dynamic Substitution:** Implementation of a masking algorithm to generate unique S-Boxes.
- **Confusion Property:** Strengthened the relationship between the key and ciphertext (Shannon's Confusion).
- **Performance Evaluation:** Achieved a **Key Sensitivity** of approximately **49.8%** over 5,000 test trials.

## Project Structure
- `/Documentation`: Full research paper and evaluation results.
- `/Analysis`: Detailed breakdown of Key Sensitivity and statistical tests.
