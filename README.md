# PE-Fingerprinter
A PE file analyzing tool that: 
  Extracts banner information (origin, last modification date, version, etc.).
  Find dependencies (imported .dll files), display them in a UML like format including their functions (Graphviz installation required beforehand), and analyzes them.
  Obtains malware scanning results from VirusTotal (Virustotal.com).
  Searches and displays known vulnerabilities from NVD based on the file's name and its version (nvd.nist.gov).
  Calculates a "safety score" based on results obtained.
  
  
  
  
  
This product uses the NVD API but is not endorsed or certified by the NVD.
This product uses the VirusTotal API but is not endorsed or certified by VirusTotal.
This application is not an Antivirus software. The use of a proper Antivirus software is recommended.
