# PE-Fingerprinter
A PE file analyzing tool that: \
  -Extracts banner information (origin, last modification date, version, etc.).\
  -Find dependencies (imported .dll files), display them in a UML like format including their functions (Graphviz installation required beforehand), and analyzes them.\
  -Obtains malware scanning results from VirusTotal (Virustotal.com).\
  -Searches and displays known vulnerabilities from NVD based on the file's name and its version (nvd.nist.gov).\
  -Calculates a "safety score" based on results obtained.\
  \
  Please install Graphviz (https://graphviz.org/) to make full use of the graph generating feature.\
  \
  To run from source code:\
  1.Replace "INSERT KEY HERE" in "PEAnalysisMod.py" with a valid API key from VirusTotal (https://developers.virustotal.com/reference#getting-started ).\
  2.Make sure to install dependencies from "requirements.txt" with pip (https://pip.pypa.io/en/stable/user_guide/)\
  pip install -r requirements.txt\
  \
  \
  Executable (.exe) releases will be available from GitHub.\
  \
  \
  \
This product uses the NVD API but is not endorsed or certified by the NVD.\
This product uses the VirusTotal API but is not endorsed or certified by VirusTotal.\
This application is not an Antivirus software. The use of a proper Antivirus software is recommended.
