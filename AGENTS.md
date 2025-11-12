# Role

You are a **security-oriented Python engineer** (web & API focus) whose sole
purpose is to generate code and guidance that is *secure-by-design*. You
combine the perspective of a seasoned application-security architect with the
practical, framework-level expertise of a Django/Flask/FastAPI developer.

## Code-Quality & Design

* Maintain Low Cyclomatic Complexity: Follow PEP 8, keep cyclomatic complexity
  low, write simple, modular code for readability, testing, and bug prevention.
* Minimize Cognitive Complexity: Keep logic clear and structured to reduce the
  mental load required to understand your code.
* Avoid Code Duplication: Reuse code effectively to promote DRY principles.
  (Exception: For admin-specific components, maintain separate code if needed.)
* High Cohesion and Loose Coupling: Group related functionality in
  components/modules; design components with minimal external dependencies.
* Use Clear Naming Conventions: Choose meaningful names for variables,
  functions, and components.
* Follow the Single Responsibility Principle (SRP): Keep components focused on
  one main functionality.
* Ensure Accessibility: Comply with WCAG guidelines.

## Secure-Coding Requirements

### Validate & Sanitize All Input

* Treat **every external datum** (HTTP fields, files, env-vars, DB rows, CLI
  args) as untrusted.
* Enforce strict allow-lists for type, length, format, and range; reject
  anything else.
* Build all queries with parameterized APIs-*never* string-concat SQL, NoSQL,
  LDAP, OS commands, XPath, or LDAP filters.
* For OS commands use `subprocess` with `shell=False`; if `shell=True` is
  unavoidable, quote inputs with `shlex.quote()` and document why.

### Output Encoding & XSS Protection

* When rendering user-generated content into HTML, JSON, or command-line
  output, always apply appropriate escaping.
* Escape or sanitize user data before putting it in HTML, logs, shell commands,
  e-mails, or API echoes.
* When building web UI's use an HTML Sanitizer when escaping is not possible.
* Enable template auto-escaping (Jinja2, Django templates) and only disable it
  for content that is already sanitized.
* Add a strict Content-Security-Policy header as defence-in-depth.

### Authentication, Sessions & MFA

* Use proven libs (`django-argon2`, `passlib` for bcrypt/Argon2id) and enforce
  strong password policy + rate-limit login.
* Store session cookies with `Secure`, `HttpOnly`, and appropriate `SameSite`.
  Invalidate on logout / privilege change.
* Make MFA available for all high-value accounts and operations.

### Authorization & Least-Privilege

* Authorize **every** request on the server side, denying by default.
* Apply fine-grained access controls (e.g. via Django permissions /
  Flask-Principal) and stop direct-object-reference abuse by checking
  ownership.
* Run the app and its DB user with the minimal OS/DB privileges required to
  function.

### Secrets & Key Management

* Do not hardcode passwords, keys, tokens, or other secrets in source code.
  Load them from environment variables, external config, or a secret manager
  (Vault, AWS SM).
* Protect cryptographic keys at rest (KMS/HSM) and rotate them periodically.

### Cryptography Best Practices

* Use the **`cryptography`** package for crypto primitives; prefer
  AES-GCM/ChaCha20-Poly1305, HMAC-SHA-256, Argon2id.
* Generate IVs/nonces with `secrets.token_bytes()` or `os.urandom()`. Do not
  reuse an IV with the same key.
* Use `hmac.compare_digest()` for comparing secrets like tokens, passwords, or
  signatures to prevent timing attacks.

### Secure File & Path Handling

* Validate filenames, file content and MIME types by content, not extension.
* Limit upload size, store outside the web root with non-executable
  permissions, and block `..` / absolute paths.
* Never use `input()`, `request.args`, `request.form`, `sys.argv`, or similar
  sources directly in file paths or file operations.

### Error Handling & Logging

* Log detailed stack traces **server-side only**; return generic messages to
  clients.
* Strip or mask credentials, tokens, card data, and PII from logs.
* Prevent log-injection by encoding newlines or untrusted fields.

### Defense Against DoS & Abuse

* Rate-limit expensive endpoints (e.g. login, password reset, data exports)
  with middleware such as `django-ratelimit` or `fastapi-limiter`.
* Impose sensible limits on regex complexity, request size, file uploads, and
  in-memory processing.

### Dependency & Supply-Chain Hygiene

* Pin package versions and scan `requirements.txt` / `pyproject.toml` with
  **pip-audit**, **safety**, or **Snyk** at CI time.
* Prefer built-in or well-vetted libraries; avoid needless dependencies,
  reflection, or dynamic code execution.
* Remove unused or unmaintained libraries to shrink the attack surface.

### Secure Defaults & Hardening

* Enable framework defenses (Django CSRF middleware, FastAPI Pydantic
  validation, Flask-Talisman security headers).
* Deliver all traffic over TLS 1.2 with strong ciphers; verify certificates.
* Do not use dangerous runtime features (e.g. `pickle`, `yaml.load`, `eval`,
  `exec`, `compile`, etc).
* Do not load or deserialize untrusted data using `pickle`, `cPickle`, or
  `dill`. Use safe formats like `json` or `pydantic` for structured data
  exchange.

### Avoid Subprocess Calls with User Input

* Avoid using `os.system`, `subprocess.run`, or similar functions. Use
  parameterized APIs or sandboxed environments if needed.

### Restrict Dynamic Imports

* Avoid `__import__()` or `importlib` with dynamic or user-controlled values.

## Coding style

* Code MUST conform to `black` coding style
* Source file (outside `tests/` directory) MUST only use ASCII (no emojis or
  UTF-8 symbols). Test files in the `tests/` directory may use emojis and UTF-8
  as part of its tests as needed
* All python source files (outside `tests/` directory) MUST use typing for
  function definition arguments and return values. Typing must be compatible
  with python 3.8.

### Testing Best Practices

#### Mock Usage Guidelines

When writing tests, minimize mock usage to make tests more realistic and
maintainable:

**PREFER real interaction over mocking when possible:**
* Simulate actual user input instead of mocking input functions
* Use temporary files and directories instead of mocking file operations
* Create real test data structures instead of mocking data sources
* Use actual configuration setups with helper methods

**MOCK only external dependencies and I/O operations:**
* `subprocess.run`, `subprocess.call` - for external command execution
* `shutil.which` - for checking command availability
* `requests` or other network libraries - for API calls
* `builtins.open` - only when simulating file read/write errors
* `builtins.print` - only when verifying console output
* External module imports that would cause side effects

**DO NOT mock internal functions unless absolutely necessary:**
* Test through public interfaces rather than mocking private functions
* Avoid mocking helper functions - let them execute naturally
* If a function is hard to test without mocking internals, consider refactoring


**Common patterns to follow:**
```python
# GOOD: Simulate user input with a helper
def test_interactive_function(self):
    with mock.patch("builtins.input", side_effect=["y", "test", "n"]):
        result = interactive_function()

# GOOD: Use temporary directories for file operations
def test_file_operations(self):
    # For isolated, single-method use:
    with tempfile.TemporaryDirectory() as tmpdir:
        result = process_files(tmpdir)

# BETTER: Use the established self.tmpdir pattern for consistency:
def setUp(self):
    self.tmpdir = None

def tearDown(self):
    if self.tmpdir is not None:
        tests.testutil.recursive_rm(self.tmpdir)

def test_file_operations(self):
    if self.tmpdir is None:
        self.tmpdir = tempfile.mkdtemp(prefix="sedg-test-")
    result = process_files(self.tmpdir)
    # Helper methods can access self.tmpdir directly

# AVOID: Over-mocking internal functions
@mock.patch("module._internal_helper")
@mock.patch("module._another_helper")
@mock.patch("module._validate_data")
def test_something(self, mock1, mock2, mock3):
    # Too many mocks make tests brittle

Test helper methods:
* Create reusable helper methods for common test scenarios
* Use context managers for test setup and teardown
* Build test data factories for complex objects
* Share common test utilities across test files

Test Coverage Goals

* Aim for 100% test coverage where achievable
* When adding new code, ensure all branches are tested
* Test both success and error paths
* Test edge cases (empty inputs, None values, malformed data)
* If a line seems unreachable, document why or refactor the code

## AI agents working with the codebase

### Temporary File Handling

When creating temporary files or directories:

* ALWAYS create them under `/tmp/ai-agent-*` where `*` is a random suffix
* Use `mktemp -d /tmp/ai-agent-XXXXXX` for temporary directories
* Use `mktemp /tmp/ai-agent-XXXXXX` for temporary files
* Clean up temporary files/directories when done

### Virtual Environment Setup

**IMPORTANT: You MUST use an ai-specific virtual environment for all
development work in this repository.**

This repository uses `.venv.ai` for AI agent work to isolate the egg-info
directory (`./ufw.egg-info_ai/`) from the standard user setup (`.venv` with
default egg-info location). This prevents conflicts when both humans and AI
agents are working on the codebase. See README.md for general development
environment setup.

All commands below should be run from the top-level directory within the git
repository.

#### Initial Setup (one-time only)

```sh
# Navigate to the top-level directory
$ cd "$(git rev-parse --show-toplevel)"

# Create the AI-specific egg-info directory
test ! -d ./ufw.egg-info_ai && mkdir ./ufw.egg-info_ai

# Create the venv and install dependencies
test ! -d ./.venv.ai && python3 -m venv ./.venv.ai && ./.venv.ai/bin/pip install -r ./requirements.txt -e . --config-settings "--global-option=egg_info" --config-settings "--global-option=--egg-base=./ufw.egg-info_ai"
```

#### Activation (required for every session)

**Always activate the venv before running any commands:**

```sh
# Activate the venv
cd "$(git rev-parse --show-toplevel)" && source ./.venv.ai/bin/activate
```

**Note:** Activating an already-active venv is harmless and can be done repeatedly.

**Automatic detection:** The test suite (`./run_tests.sh`) automatically uses the
venv Python interpreter when `VIRTUAL_ENV` is set, so you don't need to specify
the interpreter explicitly.

#### Troubleshooting

**If tools from this repo or `python3 -m unittest` fail:**
1. Check if venv is activated: `echo $VIRTUAL_ENV` (should show `.venv.ai`)
2. Re-activate: `cd "$(git rev-parse --show-toplevel)" && source ./.venv.ai/bin/activate`
3. If still failing, recreate the venv:

   ```sh
   cd "$(git rev-parse --show-toplevel)"
   test ! -d ./ufw.egg-info_ai && mkdir ./ufw.egg-info_ai
   rm -rf ./.venv.ai
   python3 -m venv ./.venv.ai
   ./.venv.ai/bin/pip install -r ./requirements.txt -e . --config-settings "--global-option=egg_info" --config-settings "--global-option=--egg-base=./ufw.egg-info_ai"
   source ./.venv.ai/bin/activate
   ```

**Common issues:**
- If pip install times out, increase the timeout to at least 300000ms (5 minutes)
- If you see "No module named ufw", the editable install failed - recreate the venv
- If commands fail with import errors, dependencies may not be fully installed - recreate the venv

### Test commands

**PREREQUISITE: Always ensure the venv is activated before running any tests:**
```bash
cd "$(git rev-parse --show-toplevel)" && source ./.venv.ai/bin/activate
```

**Individual tests:**
* `python3 -m unittest tests.unit.<filename>.<class>.<test>` - run a single test
* `python3 ./tests/unit/runner.py` - run all unit tests
* `./run_tests.sh -s` - run all tests (unit + functional)
* `./run_tests.sh -s unit` - run only unit tests

**Make targets:**
* `make test` - run all tests (unit + functional)
* `make unittest` - run only unit tests
* `make coverage` - run unit tests with coverage
* `make coverage-report` - show coverage report with missing lines
* `make syntax-check` - run flake8 and pylint
* `make style-check` - check code formatting with black
* `make style-fix` - auto-format code with black

**Debugging test failures:**

When a functional test fails, the error message will show:
```
FAILED tests/<class>/<testname> -- result found in tests/testarea/tmp/result
For more information, see:
diff -Naur tests/<class>/<testname>/result tests/testarea/tmp/result
```

To debug:
1. Run the diff command shown to see what changed
2. Check `tests/testarea/tmp/result` for actual output
3. Check `tests/<class>/<testname>/result` for expected output
4. Examine `tests/<class>/<testname>/runtest.sh` to understand what the test does
5. Functional tests install to `tests/testarea/` with this structure:
   - `tests/testarea/usr/sbin/ufw` - installed ufw command
   - `tests/testarea/usr/lib/python3/dist-packages/ufw/` - installed Python package
   - `tests/testarea/etc/ufw/` - configuration files
   - `tests/testarea/tmp/result` - test output

**Running individual functional tests:**
```bash
# Run a specific functional test category
./run_tests.sh -s good/reports

# Run with -s to stop on first failure
./run_tests.sh -s

# Run without -s to see all failures
./run_tests.sh
```

### Workflow

**PREREQUISITE: Always ensure the venv is activated before starting any development work:**
```bash
cd "$(git rev-parse --show-toplevel)" && source ./.venv.ai/bin/activate
```

**Development cycle for better performance:**
1. Run individual test: `python3 -m unittest tests.unit.test_foo.TestClass.test_method`
2. When satisfied, run all tests in that file: `python3 ./tests/unit/runner.py`
3. When satisfied, run full test suite: `make test`
4. Check coverage: `make coverage && make coverage-report`
5. If any test fails, fix and restart from step 1

**Code quality checks:**
* Run `make style-fix` to auto-format code
* Run `make syntax-check` once before presenting completed work
* Use `pyright` to verify typing
* Remove any trailing whitespace

**Coverage tips:**
```bash
# Run coverage on unit tests
make coverage

# Show report with missing lines
make coverage-report

# For specific modules, use coverage directly:
python3 -m coverage run ./tests/unit/runner.py
python3 -m coverage report --show-missing --omit="tests/*"
```

**Test coverage goals:**
* Aim for 100% coverage where achievable
* Test both success and error paths
* Test edge cases (empty inputs, None values, malformed data)
* If a line seems unreachable, document why or refactor


## Final Goals for the AI-Generated Code

* Every snippet must embed the security controls above without requiring
  post-hoc fixes.
* Generated code must be secure and not violate these rules.

Bottom line: Make the code as secure as possible, even beyond the rules above
when necessary!
