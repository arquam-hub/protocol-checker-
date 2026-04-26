Instructions here
# Protocol Checker for LLM-Based Security Protocol Analysis

This repository contains the source code, experiment outputs, and supporting artefacts for a dissertation evaluating GPT and DeepSeek on the symbolic analysis of AnB/AnBx security protocols.

## Repository contents

This project includes:

- source code for the protocol-checking and evaluation pipeline
- raw CSV outputs from chat-mode and reasoning-mode experiment runs
- audit files containing sanitised protocol inputs, prompts, and parsed model responses
- comparison and metrics outputs used to analyse performance against formal-verification ground truth

## Project overview

The system processes AnB/AnBx protocol specifications and evaluates them with large language models under a symbolic reasoning prompt. The pipeline:

1. strips comments and sanitises the protocol input
2. anonymises protocol names and filenames
3. extracts explicit goals from the protocol specification
4. submits the protocol and goals to GPT and DeepSeek models
5. records structured JSON verdicts
6. writes per-goal results to CSV
7. compares model outputs against ground-truth verdicts from formal-verification tools

## Main artefacts

The repository contains material corresponding to the dissertation experiments, including:

- chat-mode runs on the full dataset
- reasoning-mode runs on a 20-protocol subset
- a full-dataset reasoning-mode run
- comparison outputs against ground-truth files
- config.ini file included to input own API keys and can be amended according to users choice 

## Notes


- Any paths, filenames, and protocol identifiers shown in audit files were used for experimental processing and anonymisation.
- This repository is intended to accompany the dissertation submission and provide transparency for the implementation and experimental outputs.
- file path from original computer was removed from all json files due to personal safety
- folder data_raw_results contains files of generated results
- folder datac contains comparison results
- folder datarawresults contains json files 
