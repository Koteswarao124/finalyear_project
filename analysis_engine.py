import sys
import subprocess
import json
from pathlib import Path


print("Smart Contract Static Analysis Engine")
print("-------------------------------------")


# ============================================================
# 1. CHECK WHETHER A SOLIDITY FILE WAS PROVIDED
# ============================================================

if len(sys.argv) < 2:

    print("ERROR: Please provide a Solidity file.")
    print("Example:")
    print("python analysis_engine.py contracts/vulnerable.sol")

    sys.exit(1)


# ============================================================
# 2. GET THE SOLIDITY FILE PATH
# ============================================================

solidity_file = Path(sys.argv[1])


# ============================================================
# 3. CHECK IF FILE EXISTS
# ============================================================

if not solidity_file.exists():

    print("ERROR: Solidity file does not exist.")

    sys.exit(1)


# ============================================================
# 4. CHECK FILE EXTENSION
# ============================================================

if solidity_file.suffix.lower() != ".sol":

    print("ERROR: File must have a .sol extension.")

    sys.exit(1)


# ============================================================
# 5. CHECK IF FILE IS EMPTY
# ============================================================

if solidity_file.stat().st_size == 0:

    print("ERROR: Solidity file is empty.")

    sys.exit(1)


print("✓ Solidity file found:", solidity_file)
print("✓ File validation successful")


# ============================================================
# 6. READ SOLIDITY SOURCE CODE
# ============================================================

source_code = solidity_file.read_text(
    encoding="utf-8",
    errors="ignore"
)

print("\n✓ Solidity source code loaded")
print("Number of characters:", len(source_code))


# ============================================================
# 7. CHECK SOLIDITY PRAGMA
# ============================================================

if "pragma solidity" not in source_code:

    print("ERROR: Solidity pragma not found.")

    sys.exit(1)

print("✓ Solidity pragma found")


# ============================================================
# 8. CHECK CONTRACT DECLARATION
# ============================================================

if "contract " not in source_code:

    print("ERROR: No Solidity contract found.")

    sys.exit(1)

print("✓ Solidity contract detected")


# ============================================================
# 9. RUN SLITHER STATIC ANALYSIS
# ============================================================

print("\nRunning Slither static analysis...")


result = subprocess.run(

    [
        "slither",
        str(solidity_file),
        "--json",
        "slither_output.json"
    ],

    capture_output=True,

    text=True
)


print("\nSlither analysis completed.")


# ============================================================
# 10. CHECK WHETHER SLITHER CREATED JSON
# ============================================================

slither_json = Path("slither_output.json")


if not slither_json.exists():

    print("ERROR: Slither JSON output was not created.")

    print("\nSlither error:")
    print(result.stderr)

    sys.exit(1)


print("✓ Slither JSON file created")


# ============================================================
# 11. READ SLITHER JSON
# ============================================================

try:

    with open(
        slither_json,
        "r",
        encoding="utf-8"
    ) as file:

        slither_data = json.load(file)

except json.JSONDecodeError:

    print("ERROR: Slither JSON could not be read.")

    sys.exit(1)


print("✓ Slither JSON loaded")


# ============================================================
# 12. EXTRACT DETECTORS
# ============================================================

detectors = slither_data.get(
    "results",
    {}
).get(
    "detectors",
    []
)


print(
    "Number of findings:",
    len(detectors)
)


# ============================================================
# 13. DISPLAY DETECTED VULNERABILITIES
# ============================================================

print("\nDetected vulnerabilities:")


for detector in detectors:

    vulnerability = detector.get(
        "check",
        "Unknown"
    )

    impact = detector.get(
        "impact",
        "Unknown"
    )

    confidence = detector.get(
        "confidence",
        "Unknown"
    )

    description = detector.get(
        "description",
        ""
    )

    elements = detector.get(
        "elements",
        []
    )


    print("\n=============================")

    print(
        "Vulnerability:",
        vulnerability
    )

    print(
        "Impact:",
        impact
    )

    print(
        "Confidence:",
        confidence
    )

    print(
        "Evidence:",
        description
    )

    print(
        "Number of affected elements:",
        len(elements)
    )


    # ========================================================
    # 14. EXTRACT ELEMENT INFORMATION
    # ========================================================

    for element in elements:

        element_type = element.get(
            "type",
            "Unknown"
        )

        element_name = element.get(
            "name",
            "Unknown"
        )

        print(
            "Element:",
            element_type,
            element_name
        )


# ============================================================
# 15. EXTRACT SOURCE LOCATION
# ============================================================

print("\nSource locations:")


for detector in detectors:

    elements = detector.get(
        "elements",
        []
    )


    for element in elements:

        source_mapping = element.get(
            "source_mapping",
            {}
        )

        filename = source_mapping.get(
            "filename_relative",
            "Unknown"
        )

        lines = source_mapping.get(
            "lines",
            []
        )


        print("\nFile:", filename)
        print("Lines:", lines)


# ============================================================
# 16. EXTRACT ACTUAL SOURCE CODE
# ============================================================

print("\nActual source code:")


source_lines = source_code.splitlines()


for detector in detectors:

    elements = detector.get(
        "elements",
        []
    )


    for element in elements:

        source_mapping = element.get(
            "source_mapping",
            {}
        )

        lines = source_mapping.get(
            "lines",
            []
        )


        if not lines:

            continue


        print("\n-----------------------------")


        for line_number in lines:

            if 1 <= line_number <= len(source_lines):

                print(
                    f"Line {line_number}: "
                    f"{source_lines[line_number - 1].strip()}"
                )


# ============================================================
# 17. CREATE CLEAN STRUCTURED FINDINGS
# ============================================================

structured_findings = []


for detector in detectors:

    vulnerability = detector.get(
        "check",
        "Unknown"
    )

    impact = detector.get(
        "impact",
        "Unknown"
    )

    confidence = detector.get(
        "confidence",
        "Unknown"
    )

    description = detector.get(
        "description",
        ""
    )

    elements = detector.get(
        "elements",
        []
    )


    # --------------------------------------------------------
    # Store all affected elements
    # --------------------------------------------------------

    affected_elements = []

    all_lines = []

    functions = []


    for element in elements:

        element_type = element.get(
            "type",
            "Unknown"
        )

        element_name = element.get(
            "name",
            "Unknown"
        )


        source_mapping = element.get(
            "source_mapping",
            {}
        )


        filename = source_mapping.get(
            "filename_relative",
            str(solidity_file)
        )


        lines = source_mapping.get(
            "lines",
            []
        )


        # ----------------------------------------------------
        # Collect source lines
        # ----------------------------------------------------

        for line in lines:

            if line not in all_lines:

                all_lines.append(line)


        # ----------------------------------------------------
        # Collect functions
        # ----------------------------------------------------

        if element_type == "function":

            if element_name not in functions:

                functions.append(
                    element_name
                )


        # ----------------------------------------------------
        # Store affected element
        # ----------------------------------------------------

        affected_elements.append(
            {
                "type": element_type,

                "name": element_name,

                "source_file": filename,

                "lines": lines
            }
        )


    # --------------------------------------------------------
    # Extract actual code context
    # --------------------------------------------------------

    code_context = []


    for line_number in sorted(all_lines):

        if 1 <= line_number <= len(source_lines):

            code_context.append(
                {
                    "line": line_number,

                    "code": source_lines[
                        line_number - 1
                    ].strip()
                }
            )


    # --------------------------------------------------------
    # Create one finding per vulnerability
    # --------------------------------------------------------

    finding = {

        "vulnerability": vulnerability,

        "impact": impact,

        "confidence": confidence,

        "function": functions,

        "source_file": str(
            solidity_file
        ),

        "source_lines": sorted(
            all_lines
        ),

        "code_context": code_context,

        "description": description,

        "affected_elements": affected_elements
    }


    structured_findings.append(
        finding
    )


# ============================================================
# 18. SAVE STRUCTURED FINDINGS
# ============================================================

structured_output = {

    "contract": str(
        solidity_file
    ),

    "number_of_findings": len(
        structured_findings
    ),

    "findings": structured_findings
}


with open(
    "structured_findings.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        structured_output,
        file,
        indent=4
    )


print(
    "\n✓ Clean structured findings JSON created:"
)

print(
    "  structured_findings.json"
)


# ============================================================
# 19. FINAL STATUS
# ============================================================

print("\n=====================================")
print("STATIC ANALYSIS COMPLETED")
print("=====================================")

print(
    "Contract:",
    solidity_file
)

print(
    "Total vulnerabilities:",
    len(structured_findings)
)

print(
    "Output file: structured_findings.json"
)

print("=====================================")