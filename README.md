<p align="center"> 
  <!-- tool logo -->
  <img src="asset/logo.png" width="35%">
</p>

<div align="center">

  <h1 align="center">ThreatCraft</h1>

  <p align="center">
    <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/Python-v3.10.19-blue?style=for-the-badge&logo=Python">
    </a>
    <a href="https://github.com/heeyapro/ThreatCraft/">
      <img src="https://img.shields.io/badge/Github-35495E?logo=GitHub&style=for-the-badge">
    </a>
    <a href="https://graphviz.org/">
      <img src="https://img.shields.io/badge/Graphviz-v14.1.5-green?style=for-the-badge&logo=diagrams.net&logoColor=white">
    </a>
  </p>
<br><b>ThreatCraft</b> is an automated attack scenario generation tool that combines rule-based reasoning with large language models to produce structurally valid and realistic attack scenarios while reducing expert dependency, inconsistency, and hallucinated outputs.
<br/>

<br>
<h3 align="center">##Demo Video</h3>
<p align="center">
  <a href="https://youtu.be/nrIHEKDLp2E">
    <img src="https://img.youtube.com/vi/nrIHEKDLp2E/maxresdefault.jpg" 
         alt="ThreatCraft Demo Video" 
         width="700">
  </a>
</p>


</br>
</div>

<!-- TABLE OF CONTENTS -->
<h2 id="table-of-contents"> :book: Table of Contents</h2>

<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#overview"> ➤ Overview</a></li>
    <li><a href="#project-files-description"> ➤ Project Files Description</a></li>
    <li><a href="#installation"> ➤ Installation</a></li>
    <li><a href="#usage-example"> ➤ Usage Example </a></li>
  </ol>
</details>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="overview"> :compass: Overview</h2>

<img src="asset/WorkFlow-1.png">

<!--  -->


<p align="justify">

ThreatCraft is an automated attack scenario generation framework that combines a rule-based attack reasoning engine with LLM-based scenario generation. It is designed to address two key limitations of existing approaches: (i) rule-based systems rely on extensive manual rule engineering, and (ii) LLM-based approaches may generate hallucinated or structurally invalid attack scenarios.

</p>

---

### 🔁 1. Rule-Based Engine Layer

<p align="justify">

The overall architecture shown in Figure above is organized as a sequential pipeline:

</p>

- 📌 <b>Input Data (DFD / System Description)</b>  
  → DataFlow Diagram(DFD), Attack Mode, Target Asset
  → (Figure: left-most input block)

- 📌 <b>Rule-Based Attack Engine</b>  
  → Constructs structured attack paths using:
  - Integrated Attack Library (MITRE ATT&CK, CVE, CWE, domain KBs)
  - Asset & attack-step dependency model  
  - Unified Kill Chain (UKC) phase structuring  
  → (Figure: upper-middle “Rule Engine” block which is composed of 'Attack Scenario' and 'Risk Value Determination' block)

- 📌 <b>Risk Assessment Module</b>  
  → Evaluates attack paths using:
  - Feasibility (attack vector: network/local/physical/etc.)
  - Impact (SFOP + asset criticality)  
  → (Figure: branch under rule engine → “Risk Matrix”)

---

### 🤖 2. LLM-Guided Threat Refinement Layer

<p align="justify">

The system-level outputs are not final results. They are used as grounded constraints for LLM-based refinement.

</p>

- 📌 <b>Generator Agent</b>  
  → Expands system-level paths into function-level attack scenarios  
  → Injects vulnerability context (CWE / CVE / EMB3D mapping)  
  → (Figure: LLM block – “Generator”)
  
- 📌 <b>Reviewer Agent</b>  
  → Converts structured attack paths into natural-language reasoning  
  → Validates logical consistency against attack knowledge base  
  → (Figure: LLM block – “Reviewer”)
  
---

### 📊 3. Output 

<p align="justify">

The final output is a structured threat report that includes:

</p>

- 🧩 Function-level attack scenarios
- 🧩 System-level validated attack graph
- 🧩 Risk scores (feasibility × impact)
- 🧩 Asset-level vulnerability mapping

→ (Figure: bottom/right output block)

---

### 🎯 Key Insight of the Architecture

<p align="justify">

ThreatCraft is not a pure LLM system nor a pure rule engine. Instead, it is a <b>two-stage constrained generation framework</b> where:
</p>

- Rule-based reasoning defines the “what is possible”
- LLM defines the “how it actually happens”
- Knowledge base grounding ensures “real-world feasibility”

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="project-files-description"> :file_folder: Project Files Description</h2>

```bash
ThreatCraft/
├── asset/                          # Static assets (figures, logo, references)
│   ├── logo.png                    # Project logo used in README/UI
│   ├── WorkFlow-1.png              # System architecture diagram (paper figure)
│   └── UKC_document.pdf            # Unified Kill Chain reference document
│
├── code/                           # Core implementation directory
│   │
│   ├── frontend/                   # GUI + orchestration layer
│       ├── tool_attack_paths.py           # main entry point (GUI launcher)
│       ├── automotive/                    # automotive Domain frontend
│           ├── tool_attack_paths_automotive.py         # Automotive entry point (GUI launcher)
│           ├── tool_threat_mapper_automotive.py        # Automotive Middleware between GUI and backend
│           ├── hierarchy_data_automotive.json          # Automotive CVE–CWE–EMB3D mapping dataset
│       ├── ics/                           # ics Domain frontend
│           ├── tool_attack_paths_ics.py                # ics entry point (GUI launcher)
│           ├── tool_threat_mapper_ics.py               # ics Middleware between GUI and backend
│           ├── hierarchy_data_ics.json                 # ics CVE–CWE–EMB3D mapping dataset
│       ├── enterprise/                    # enterprise Domain frontend
│           ├── tool_attack_paths_enterprise.py         # enterprise entry point (GUI launcher)
│           ├── tool_threat_mapper_enterprise.py        # enterprise Middleware between GUI and backend
│           ├── hierarchy_data_enterprise.json          # enterprise CVE–CWE–EMB3D mapping dataset
│   │
│   └── backend/                    # Threat reasoning & attack graph engine
│       ├── parse_attack_graph_automotive.py       # automotive attack scenario generator
│       ├── parse_attack_graph_ics.py              # ics attack scenario generator
│       ├── parse_attack_graph_enterprise.py       # enterprise attack scenario generator
│       │
│       └── threat_library/         # Structured threat intelligence database
│           ├── impact_feasability_map.json        # Risk scoring model (severity × feasibility)
│           ├── automotive/                        # automotive json
│               ├── asset_to_threats_automotive.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_automotive.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_automotive.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_automotive.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_automotive.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic
│           ├── ics/                              # ics json
│               ├── asset_to_threats_ics.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_ics.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_ics.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_ics.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_ics.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic
│           ├── enterprise/                        # enterprise json
│               ├── asset_to_threats_enterprise.json
│               │   # Maps assets → applicable threats & tactics
│               │
│               ├── attack_vector_feasibility_enterprise.json
│               │   # Threat metadata (tactic, feasibility, attack vector)
│               │
│               ├── dependency_enterprise.json
│               │   # Asset/threat dependency constraints for attack chaining
│               │
│               ├── impact_map_enterprise.json
│               │   # SFOP impact model (Safety / Financial / Operational / Privacy)
│               │
│               └── threat_to_tactic_enterprise.json
│                   # Threat → MITRE ATT&CK tactic mapping & ordering logic

└── example/
        ├── Automotive_DFD.tm7         # Example DFD
        ├── ICS_DFD_B.tm7              # Example DFD
        ├── Enterprise_DFD.tm7         # Example DFD
        ├── _ag_tmp_184849195185.html  # Output Report in FTML format
        └── _ag_tmp_184849195185.pdf   # Output Report in PDF format
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="installation"> :gear: Installation</h2>

<p align="justify">
  Follow the steps below to set up and run <b>ThreatCraft</b> in your local environment.
</p>

<ol>
  <li>
    <b>Install Graphviz</b><br/>
    Download and install Graphviz from the official site:<br/>
    https://graphviz.org/download/<br/><br/>
    After installation, make sure to add Graphviz to your system <b>PATH</b> (required for rendering attack graphs).
  </li>

  <li>
    <b>Install Python dependencies</b><br/>
    Run the following command in your project environment:
    <pre><code>pip install graphviz pillow</code></pre>
  </li>

  <li>
    <b>Verify backend prerequisites</b><br/>
    Ensure Python version is <b>3.10+</b> and Graphviz is accessible from the terminal:
    <pre><code>dot -V</code></pre>
  </li>

  <li>
    <b>Run ThreatCraft</b><br/>
    Navigate to the frontend directory and execute:
    <pre><code>cd code/frontend
python tool_attack_paths.py</code></pre>
  </li>
</ol>

<p align="justify">
  Once executed successfully, the system will launch the ThreatCraft and the GUI will be displayed on your screen.
</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)

<!-- OVERVIEW -->
<h2 id="usage-example"> :rocket: Usage Example</h2>

### 🎯 Scenario Definition: Remote Attack on Vehicle Door System

We assume an attacker attempting to remotely compromise a vehicle door control system.

- **Target Asset**: `Door`
- **Trust Boundary**: `External Vehicle Boundary`
- **Attack Mode**: `Remote`
<img src="asset/20260211_172126.png" alt="DFD" width="100%">

---
### **0. Select The Target Domain To Be Analysed**

Select the target domain for the system under analysis. In this tutorial, the attack scenario targets a vehicle, so choose the Automotive Vehicle domain.

<img src="asset/20260508_130606.png" alt="DFD" width="100%">

---

### **1. Launch ThreatCraft & Configure Analysis Context**

After starting the application, the GUI dashboard is displayed.

Configure the analysis environment as follows:

- 📂 **DFD File Selection**  
  Load the target system model (`TM7 file`) representing the vehicle architecture.

- 🧠 **LLM Configuration**  
  - Select LLM backend (e.g., GPT-based model)
  - Input valid API key

- 🎯 **Target Definition**
  - Select **Target Asset**: `Door`

- 🌐 **Trust Boundary Selection**
  - Define system boundary: `External Vehicle Boundary`

- ⚔️ **Attack Mode**
  - Set attacker capability: `Remote`

- ▶️ Click **`Run Analysis`**

> 📌 Note: All required threat intelligence libraries (CVE/CWE/EMB3D mappings, dependency graphs, risk models) are preloaded via *Library File Settings* by default.

<img src="asset/20260502_180259.png" alt="DFD" width="100%">

---

### **2. Configure Implementation Detail of Assets**

Next, we define the implementation details for each asset. 

For instance, as shown in the figure below a TCU may run a Linux operating system with multiple implementation characteristics:
- loadable kernel modules (PID-23L1) and
- Linux namespace isolation (PID-23L2). 

After adding the implementation details to the assets, click “OK”.

> 📌 Note: It is not mandatory to provide implementation details for all assets.
 
<img src="asset/20260502_181157.png" alt="config" width="100%">

---

### **3. Check the Analysis Result**

The result window consists of three tabs:

---

#### **1) Asset Mapping**
Each CWE threat is mapped to a specific asset. Note that CWE entries for an asset are not provided by default; they become available only after defining the asset’s implementation details, as described in Subsection 2 (“Configure Implementation Details of Assets”).

<img src="asset/20260502_183945.png" alt="analysis_result1" width="100%">

---

#### **2) Attack Paths**
Each identified attack path is summarised. Each path represents a unique combination of assets and threats.

<img src="asset/20260502_181549.png" alt="analysis_result2" width="100%">

---

#### **3) AI Analysis**
The AI analysis is divided into two levels:

---

##### **Vehicle-Level Review**
For each attack path, the tool assesses its likelihood (confidence level) and provides mitigation recommendations. Furthermore, it performs a comprehensive evaluation across all attack paths to identify and present the highest-risk path.

<img src="asset/20260502_185712.png" alt="analysis_result3" width="100%">

---

##### **Functional-Level Review**
The tool evaluates the most critical vulnerabilities within each asset in the aggregated attack tree from an SFOP (Safety, Financial, Operational, Privacy) perspective, and presents the results for each asset-specific vulnerability accordingly.

<img src="asset/20260502_185751.png" alt="analysis_result4" width="100%">


> 📌 Note: You could save its results into JSON, CSV respectively, and also, you can check this whole results displayed in TARA Report(check ```example/_ag_tmp_184849195185.html```)

<img src="asset/20260502_192452.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192500.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192514.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192521.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192527.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192533.png" alt="analysis_result4" width="100%">
<img src="asset/20260502_192541.png" alt="analysis_result4" width="100%">
  
![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/solar.png)


## ⚖️ License

This project is licensed under the [MIT License](LICENSE).

---

## ✉️ Contact

- **Seungjoo Kim (Corresponding Author)** — Professor, Korea University, School of Cybersecurity (skim71@korea.ac.kr)
- **Dohee Kang (First author)** — M.S. course, Korea University, School of Cybersecurity (kangdohee1211@korea.ac.kr)
- **Geunwoo Baek (Third author)** - M.S, Korea University, School of Cybersecurity (sinse100@korea.ac.kr) 
- **Our Lab** — [Security Automation aNd Engineering Lab (SANE Lab)](https://sites.google.com/view/seceng/home)
---
