# REQUIREMENTS

ThreatCraft is provided as a source-code artifact and runs as a Python-based GUI application in a local environment.

## Hardware Requirements

ThreatCraft does not depend on any special hardware.

## Software Requirements

System-level software:

- Windows 10 or Windows 11
- Python 3.10 or later
- Graphviz system package

Python dependency packages:

- graphviz
- pillow

Graphviz must be installed on the host system and added to the system PATH. ThreatCraft uses the Graphviz `dot` executable to render attack graphs.

To verify that Graphviz is installed correctly, run the following command:

```bash
dot -V
```

Install the required Python packages with the following command:

```bash
pip install graphviz pillow
```

## External Service Requirements

GPT and Gemini API keys are required.

