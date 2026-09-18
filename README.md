# AEGIS
## AI Code Fix Integrity Auditor

Aegis is a local Python CLI application that audits AI-generated code patches for security risks and logical errors.

## Project Structure

```
aegis/
├── src/
│   ├── __init__.py
│   ├── data_loader.py
│   ├── semantic_analyzer.py
│   ├── safety_scanner.py
│   └── cli.py
├── notebooks/        # Experiments and prototyping
├── models/           # Trained model weights
├── tests/            # Unit and integration tests
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
