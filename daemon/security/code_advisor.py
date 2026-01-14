"""
Code Vulnerability Advisor - LLM-Powered Security Scanner
Advisory-only code scanner using local LLMs (Ollama) for vulnerability detection.
"""

import os
import json
import hashlib
import time
import logging
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)

# Optional Ollama import with graceful fallback
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class AdvisorySeverity(Enum):
    """Severity level of security advisory"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdvisoryStatus(Enum):
    """Status of security advisory"""
    PENDING = "pending"  # Not yet reviewed
    REVIEWED = "reviewed"  # Marked as reviewed
    WATCHING = "watching"  # On watch list
    IGNORED = "ignored"  # Explicitly ignored
    ISOLATED = "isolated"  # Module isolated in quarantine


@dataclass
class SecurityAdvisory:
    """A single security advisory finding"""
    advisory_id: str
    file_path: str
    line_start: int
    line_end: int
    issue_type: str
    severity: AdvisorySeverity
    confidence: float  # 0.0 - 1.0
    explanation: str
    suggested_readings: List[str]
    recommended_action: str
    code_snippet: Optional[str] = None
    status: AdvisoryStatus = AdvisoryStatus.PENDING
    created_at: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_note: Optional[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = str(time.time())

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> 'SecurityAdvisory':
        """Create from dictionary"""
        data = data.copy()
        data['severity'] = AdvisorySeverity(data['severity'])
        data['status'] = AdvisoryStatus(data['status'])
        return cls(**data)

    def get_summary(self) -> str:
        """Get short summary for display"""
        return f"[{self.severity.value.upper()}] {self.issue_type} in {self.file_path}:{self.line_start}"


@dataclass
class ScanResult:
    """Result of a code security scan"""
    scan_id: str
    repo_path: str
    commit_hash: Optional[str]
    model_used: str
    files_scanned: int
    advisories: List[SecurityAdvisory]
    scan_duration: float
    timestamp: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'scan_id': self.scan_id,
            'repo_path': self.repo_path,
            'commit_hash': self.commit_hash,
            'model_used': self.model_used,
            'files_scanned': self.files_scanned,
            'advisories': [adv.to_dict() for adv in self.advisories],
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp
        }


class CodeVulnerabilityAdvisor:
    """
    Advisory-only code vulnerability scanner using local LLMs.

    Design Principles:
    - Advisory Only: No automatic actions or blocking
    - Human-in-the-Loop: All findings require explicit user review
    - Local-First: Scans run on-device using trusted local models
    - Privacy-Preserving: No code leaves device
    - Educational: Every flag includes context and resources
    """

    # File extensions to scan (code files only)
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp',
        '.go', '.rs', '.rb', '.php', '.sh', '.bash', '.sql', '.yaml', '.yml',
        '.json', '.xml', '.html', '.css', '.scss'
    }

    # Default model for security scanning
    DEFAULT_MODEL = "llama3.1:8b-instruct-q6_K"

    # Maximum file size to scan (bytes)
    MAX_FILE_SIZE = 1024 * 1024  # 1MB

    def __init__(self, model: Optional[str] = None, storage_dir: Optional[str] = None):
        """
        Initialize code vulnerability advisor.

        Args:
            model: Ollama model to use (default: llama3.1:8b-instruct-q6_K)
            storage_dir: Directory to store scan results and advisories
        """
        self.model = model or self.DEFAULT_MODEL
        self.storage_dir = Path(storage_dir or '/var/lib/boundary-daemon/security/')
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Storage subdirectories
        self.scans_dir = self.storage_dir / 'scans'
        self.scans_dir.mkdir(exist_ok=True)
        self.advisories_dir = self.storage_dir / 'advisories'
        self.advisories_dir.mkdir(exist_ok=True)

        # Check Ollama availability
        self.ollama_available = OLLAMA_AVAILABLE
        if self.ollama_available:
            try:
                self.client = ollama.Client()
                # Test connection
                self.client.list()
            except Exception as e:
                logger.warning(f"Ollama client error: {e}")
                self.ollama_available = False

        logger.info(f"CodeVulnerabilityAdvisor initialized:")
        logger.info(f"  Model: {self.model}")
        logger.info(f"  Ollama available: {self.ollama_available}")
        logger.info(f"  Storage: {self.storage_dir}")

    def is_available(self) -> bool:
        """Check if advisor is available (Ollama running)"""
        return self.ollama_available

    def _generate_scan_id(self, repo_path: str) -> str:
        """Generate unique scan ID"""
        data = f"{repo_path}:{time.time()}".encode()
        return hashlib.sha256(data).hexdigest()[:16]

    def _generate_advisory_id(self, file_path: str, line_start: int) -> str:
        """Generate unique advisory ID"""
        data = f"{file_path}:{line_start}:{time.time()}".encode()
        return hashlib.sha256(data).hexdigest()[:16]

    def _is_scannable_file(self, file_path: Path) -> bool:
        """Check if file should be scanned"""
        # Check extension
        if file_path.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
            return False

        # Check if file is too large
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except Exception:
            return False

        # Skip common non-code directories
        skip_dirs = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'build', 'dist'}
        for part in file_path.parts:
            if part in skip_dirs:
                return False

        return True

    def _get_scannable_files(self, repo_path: str) -> List[Path]:
        """Get list of files to scan in repository"""
        repo = Path(repo_path)
        if not repo.exists():
            return []

        files = []
        if repo.is_file():
            if self._is_scannable_file(repo):
                files.append(repo)
        else:
            for file_path in repo.rglob('*'):
                if file_path.is_file() and self._is_scannable_file(file_path):
                    files.append(file_path)

        return files

    def _read_file_safe(self, file_path: Path) -> Optional[str]:
        """Safely read file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return None

    def _build_security_prompt(self, code: str, file_path: str, language: str) -> str:
        """
        Build security analysis prompt for LLM.

        This is a critical component - the prompt engineering determines
        the quality of vulnerability detection.
        """
        prompt = f"""You are a security-focused code reviewer. Analyze the following {language} code for potential security vulnerabilities.

Focus on:
- SQL injection risks
- Command injection vulnerabilities
- Cross-site scripting (XSS) potential
- Insecure deserialization
- Path traversal vulnerabilities
- Hardcoded secrets or credentials
- Weak cryptography or hashing
- Authentication/authorization bypasses
- Race conditions
- Buffer overflows or memory issues

For each issue found, provide:
1. Issue Type (e.g., "SQL Injection", "XSS")
2. Severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)
3. Confidence (0-100%)
4. Line numbers affected
5. Clear explanation why this is a problem
6. Recommended fix or mitigation
7. Relevant resources (OWASP, CWE references)

File: {file_path}

Code:
```{language}
{code}
```

Respond ONLY with JSON array of findings in this format:
[
  {{
    "issue_type": "SQL Injection",
    "severity": "HIGH",
    "confidence": 85,
    "line_start": 42,
    "line_end": 45,
    "explanation": "Query built with string concatenation using user input",
    "recommended_action": "Use parameterized queries or ORM",
    "suggested_readings": ["OWASP SQL Injection Prevention", "CWE-89"]
  }}
]

If no issues found, respond with: []
"""
        return prompt

    def _parse_llm_response(self, response: str, file_path: str) -> List[SecurityAdvisory]:
        """Parse LLM response into SecurityAdvisory objects"""
        advisories = []

        try:
            # Try to extract JSON from response
            # LLMs sometimes wrap JSON in markdown code blocks
            response = response.strip()
            if response.startswith('```'):
                # Extract content between code fences
                lines = response.split('\n')
                json_lines = []
                in_code = False
                for line in lines:
                    if line.startswith('```'):
                        in_code = not in_code
                        continue
                    if in_code:
                        json_lines.append(line)
                response = '\n'.join(json_lines)

            findings = json.loads(response)

            for finding in findings:
                # Map severity string to enum
                severity_str = finding.get('severity', 'MEDIUM').upper()
                try:
                    severity = AdvisorySeverity[severity_str]
                except KeyError:
                    severity = AdvisorySeverity.MEDIUM

                # Create advisory
                advisory = SecurityAdvisory(
                    advisory_id=self._generate_advisory_id(file_path, finding.get('line_start', 0)),
                    file_path=file_path,
                    line_start=finding.get('line_start', 0),
                    line_end=finding.get('line_end', finding.get('line_start', 0)),
                    issue_type=finding.get('issue_type', 'Unknown'),
                    severity=severity,
                    confidence=finding.get('confidence', 50) / 100.0,
                    explanation=finding.get('explanation', ''),
                    suggested_readings=finding.get('suggested_readings', []),
                    recommended_action=finding.get('recommended_action', ''),
                    code_snippet=finding.get('code_snippet')
                )
                advisories.append(advisory)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            logger.warning(f"Response: {response[:200]}...")
        except Exception as e:
            logger.warning(f"Error parsing advisories: {e}")

        return advisories

    def _get_language_from_extension(self, file_path: Path) -> str:
        """Get language name from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.sh': 'bash',
            '.bash': 'bash',
            '.sql': 'sql'
        }
        return ext_map.get(file_path.suffix.lower(), 'unknown')

    def scan_file(self, file_path: str) -> List[SecurityAdvisory]:
        """
        Scan a single file for vulnerabilities.

        Args:
            file_path: Path to file to scan

        Returns:
            List of SecurityAdvisory objects
        """
        if not self.ollama_available:
            logger.error("Ollama not available. Install ollama and start the service.")
            return []

        file = Path(file_path)
        if not file.exists() or not self._is_scannable_file(file):
            logger.info(f"File not scannable: {file_path}")
            return []

        # Read file
        code = self._read_file_safe(file)
        if not code:
            return []

        # Get language
        language = self._get_language_from_extension(file)

        # Build prompt
        prompt = self._build_security_prompt(code, str(file), language)

        try:
            # Call LLM
            logger.info(f"Scanning {file_path} with {self.model}...")
            response = self.client.generate(
                model=self.model,
                prompt=prompt,
                options={
                    'temperature': 0.1,  # Low temperature for consistent analysis
                    'num_predict': 2048  # Allow detailed responses
                }
            )

            # Parse response
            advisories = self._parse_llm_response(response['response'], str(file))

            logger.info(f"  Found {len(advisories)} potential issue(s)")

            return advisories

        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return []

    def scan_repository(self, repo_path: str, commit_hash: Optional[str] = None) -> ScanResult:
        """
        Scan entire repository for vulnerabilities.

        Args:
            repo_path: Path to repository root
            commit_hash: Optional git commit hash for tracking

        Returns:
            ScanResult with all advisories
        """
        start_time = time.time()
        scan_id = self._generate_scan_id(repo_path)

        logger.info("=" * 70)
        logger.info(f"SECURITY SCAN: {repo_path}")
        logger.info("=" * 70)
        logger.info(f"Scan ID: {scan_id}")
        logger.info(f"Model: {self.model}")
        if commit_hash:
            logger.info(f"Commit: {commit_hash}")

        # Get scannable files
        files = self._get_scannable_files(repo_path)
        logger.info(f"Found {len(files)} scannable file(s)")

        # Scan each file
        all_advisories = []
        for i, file_path in enumerate(files, 1):
            logger.info(f"[{i}/{len(files)}] Scanning: {file_path.relative_to(repo_path)}")
            advisories = self.scan_file(str(file_path))
            all_advisories.extend(advisories)

        # Create scan result
        duration = time.time() - start_time
        result = ScanResult(
            scan_id=scan_id,
            repo_path=repo_path,
            commit_hash=commit_hash,
            model_used=self.model,
            files_scanned=len(files),
            advisories=all_advisories,
            scan_duration=duration,
            timestamp=str(time.time())
        )

        # Save scan result
        self._save_scan_result(result)

        # Save individual advisories
        for advisory in all_advisories:
            self._save_advisory(advisory)

        logger.info("=" * 70)
        logger.info("SCAN COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Files scanned: {result.files_scanned}")
        logger.info(f"Advisories: {len(result.advisories)}")
        logger.info(f"Duration: {duration:.1f}s")
        logger.info("=" * 70)

        return result

    def _save_scan_result(self, result: ScanResult):
        """Save scan result to disk"""
        scan_file = self.scans_dir / f'{result.scan_id}.json'
        with open(scan_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)

    def _save_advisory(self, advisory: SecurityAdvisory):
        """Save advisory to disk"""
        advisory_file = self.advisories_dir / f'{advisory.advisory_id}.json'
        with open(advisory_file, 'w') as f:
            json.dump(advisory.to_dict(), f, indent=2)

    def load_advisories(self, status_filter: Optional[AdvisoryStatus] = None) -> List[SecurityAdvisory]:
        """
        Load advisories from storage.

        Args:
            status_filter: Optional filter by status

        Returns:
            List of SecurityAdvisory objects
        """
        advisories = []
        for advisory_file in self.advisories_dir.glob('*.json'):
            try:
                with open(advisory_file, 'r') as f:
                    data = json.load(f)
                    advisory = SecurityAdvisory.from_dict(data)

                    if status_filter is None or advisory.status == status_filter:
                        advisories.append(advisory)
            except Exception as e:
                logger.warning(f"Failed to load {advisory_file}: {e}")

        # Sort by severity (critical first) then timestamp
        severity_order = {
            AdvisorySeverity.CRITICAL: 0,
            AdvisorySeverity.HIGH: 1,
            AdvisorySeverity.MEDIUM: 2,
            AdvisorySeverity.LOW: 3,
            AdvisorySeverity.INFO: 4
        }
        advisories.sort(key=lambda a: (severity_order[a.severity], a.created_at), reverse=True)

        return advisories

    def update_advisory_status(self, advisory_id: str, status: AdvisoryStatus,
                              review_note: Optional[str] = None) -> bool:
        """
        Update advisory status.

        Args:
            advisory_id: Advisory ID
            status: New status
            review_note: Optional note explaining the status change

        Returns:
            True if updated successfully
        """
        advisory_file = self.advisories_dir / f'{advisory_id}.json'
        if not advisory_file.exists():
            return False

        try:
            with open(advisory_file, 'r') as f:
                data = json.load(f)

            data['status'] = status.value
            data['reviewed_at'] = str(time.time())
            if review_note:
                data['review_note'] = review_note

            with open(advisory_file, 'w') as f:
                json.dump(data, f, indent=2)

            return True
        except Exception as e:
            logger.error(f"Error updating advisory: {e}")
            return False

    def get_summary_stats(self) -> Dict:
        """Get summary statistics of all advisories"""
        advisories = self.load_advisories()

        stats = {
            'total': len(advisories),
            'by_severity': {s.value: 0 for s in AdvisorySeverity},
            'by_status': {s.value: 0 for s in AdvisoryStatus}
        }

        for advisory in advisories:
            stats['by_severity'][advisory.severity.value] += 1
            stats['by_status'][advisory.status.value] += 1

        return stats


if __name__ == '__main__':
    # Test code vulnerability advisor
    print("Testing Code Vulnerability Advisor...\n")

    advisor = CodeVulnerabilityAdvisor()

    if not advisor.is_available():
        print("Ollama not available. Install with:")
        print("  curl https://ollama.ai/install.sh | sh")
        print("  ollama pull llama3.1:8b-instruct-q6_K")
        print("\nCode advisor test complete (no Ollama).")
    else:
        # Show stats
        stats = advisor.get_summary_stats()
        print(f"Advisory Stats: {stats}\n")

        # Test with a simple vulnerable code snippet
        import tempfile
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        temp_file.write('''
# Example vulnerable code
import os
import subprocess

def run_command(user_input):
    # Command injection vulnerability
    os.system("ls " + user_input)

def query_database(username):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    # execute query...

def render_page(user_content):
    # XSS vulnerability
    html = "<div>" + user_content + "</div>"
    return html
''')
        temp_file.close()

        print(f"Scanning test file: {temp_file.name}\n")
        advisories = advisor.scan_file(temp_file.name)

        print(f"\n{len(advisories)} advisories generated:")
        for adv in advisories:
            print(f"\n{adv.get_summary()}")
            print(f"  Confidence: {adv.confidence:.0%}")
            print(f"  {adv.explanation}")

        # Cleanup
        os.unlink(temp_file.name)

        print("\nCode advisor test complete.")
