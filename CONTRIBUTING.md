# Contributing to HOMESERVER Vault Management Suite

Thank you for your interest in contributing to the HOMESERVER Vault Management Suite. This is a **security-critical infrastructure component** that manages encrypted storage, VPN integration, and system orchestration. We welcome contributions that improve security, reliability, and functionality.

## About This Repository

The Vault Management Suite provides enterprise-grade system administration tools for HOMESERVER:
- LUKS encrypted drive management
- Systemd service integration
- VPN network namespace isolation
- Automated system initialization
- Secure key management integration

**Security Impact**: These scripts manage encrypted storage and privileged system operations. Security issues could:
- Expose encrypted data
- Compromise system initialization
- Allow privilege escalation
- Affect service availability and integrity

We review all contributions with security and reliability as top priorities.

## Ways to Contribute

### High-Value Contributions

- **Security improvements**: Strengthen encryption handling, access controls, or privilege management
- **Bug fixes**: Address security issues, race conditions, or error handling gaps
- **Reliability improvements**: Better error recovery, logging, or state management
- **Documentation**: Clarify usage, security model, or operational procedures
- **Testing**: Validate security properties, edge cases, and failure modes
- **Feature additions**: New functionality that aligns with HOMESERVER architecture

### Security Vulnerability Reporting

**DO NOT** open public issues for security vulnerabilities.

If you discover a security issue:
1. **Email privately**: security@arpaservers.com or owner@arpaservers.com
2. **Include details**: Description, reproduction steps, security impact
3. **Provide specifics**: Affected scripts, configuration, potential exploits
4. **Suggest fixes**: If you have a solution, include it
5. **Wait for response**: We'll acknowledge within 48 hours

We'll work with you on responsible disclosure and credit you appropriately.

## Getting Started

### Prerequisites

- **Shell scripting**: Advanced Bash proficiency
- **Python**: For transmission.py and other Python scripts
- **Linux systems**: Deep understanding of systemd, LUKS, networking
- **Security knowledge**: Encryption, privilege management, secure operations
- **System administration**: Experience managing production infrastructure

### Repository Setup

1. **Fork the repository** on GitHub:
   ```bash
   git clone git@github.com:YOUR_USERNAME/vault.git
   cd vault
   ```

2. **Add upstream remote**:
   ```bash
   git remote add upstream git@github.com:homeserversltd/vault.git
   ```

3. **Study the architecture**: Review README.md and existing scripts

4. **Test environment**: Set up a VM or test system (never test on production!)

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b security/your-improvement
# or
git checkout -b feature/your-feature
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes

**For shell scripts:**
- Input validation: Sanitize all user inputs and file paths
- Error handling: Check all command return codes, fail safely
- Logging: Use consistent logging with appropriate verbosity
- Privilege handling: Minimize privilege duration, check permissions
- Secure cleanup: Handle temp files, mount points, locks properly

**For Python scripts:**
- Type safety: Use type hints
- Error handling: Comprehensive exception handling
- Logging: Use Python logging module with proper levels
- Resource cleanup: Use context managers, proper try/finally blocks
- Security: Validate inputs, sanitize command arguments

### 3. Test Thoroughly

Testing is **mandatory**, especially for system-level changes. See [Testing Requirements](#testing-requirements).

### 4. Commit and Push

```bash
git add .
git commit -m "Detailed, descriptive commit message"
git push origin feature/your-feature
```

### 5. Open a Pull Request

Include comprehensive description and testing details.

## Code Quality Standards

### Shell Script Best Practices

**Error Handling:**
```bash
# GOOD: Comprehensive error handling
set -euo pipefail  # Exit on error, undefined vars, pipe failures

mount_device() {
    local device="$1"
    local mountpoint="$2"
    
    if [[ ! -b "$device" ]]; then
        log_error "Device $device does not exist"
        return 1
    fi
    
    if ! mount "$device" "$mountpoint"; then
        log_error "Failed to mount $device"
        return 1
    fi
    
    log_info "Successfully mounted $device at $mountpoint"
    return 0
}
```

**Input Validation:**
```bash
# GOOD: Validate before use
validate_device() {
    local device="$1"
    
    # Check format
    if [[ ! "$device" =~ ^/dev/sd[a-z][0-9]*$ ]]; then
        log_error "Invalid device format: $device"
        return 1
    fi
    
    # Check existence
    if [[ ! -b "$device" ]]; then
        log_error "Device does not exist: $device"
        return 1
    fi
    
    return 0
}
```

**Secure Temp Files:**
```bash
# GOOD: Secure temporary directory with cleanup
TEMP_DIR=$(mktemp -d) || exit 1
chmod 700 "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM
```

**Lock Files:**
```bash
# GOOD: Prevent concurrent execution
LOCK_FILE="/var/lock/vault-operation.lock"

acquire_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        log_error "Another instance is running"
        return 1
    fi
    trap 'rmdir "$LOCK_FILE"' EXIT
    return 0
}
```

### Python Code Best Practices

**Type Safety:**
```python
from typing import Optional, Dict, List
import subprocess

def execute_command(
    command: List[str],
    timeout: Optional[int] = 30
) -> subprocess.CompletedProcess:
    """Execute command with timeout and error handling."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(command)}")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.stderr}")
        raise
```

**Resource Management:**
```python
# GOOD: Context managers ensure cleanup
from contextlib import contextmanager

@contextmanager
def network_namespace(namespace: str):
    """Context manager for network namespace operations."""
    create_namespace(namespace)
    try:
        yield namespace
    finally:
        cleanup_namespace(namespace)

# Usage
with network_namespace("vpn_ns") as ns:
    # Operations in namespace
    pass
# Automatic cleanup on exit or exception
```

## Testing Requirements

**Comprehensive testing is required for all changes.**

### Required Testing

1. **Functional testing**: Core operations work as expected
2. **Error handling**: Test failure modes and error paths
3. **Security testing**: Verify permissions, access controls, encryption
4. **Integration testing**: Works with HOMESERVER services
5. **Cleanup testing**: Proper cleanup on success and failure
6. **Idempotency testing**: Safe to run multiple times

### Testing Documentation

Include in your PR:

```markdown
## Testing Performed

### Functional Tests
- Mounted LUKS encrypted device: SUCCESS
- Unmounted cleanly: SUCCESS
- Systemd service generated correctly: VERIFIED
- Integration with keyman: VERIFIED

### Error Handling Tests
- Invalid device name: REJECTED with error
- Non-existent device: HANDLED gracefully
- Mount failure: CLEANUP executed properly
- Concurrent execution: BLOCKED with lock file

### Security Tests
- File permissions: CORRECT (600/700 for sensitive files)
- No sensitive data in logs: VERIFIED
- Proper privilege handling: VERIFIED
- Encryption passphrase not exposed: CONFIRMED

### Integration Tests
- Works with HOMESERVER init system: VERIFIED
- Compatible with existing services: CONFIRMED
- No conflicts with other vault scripts: TESTED

### Cleanup Tests
- Temp files removed on success: VERIFIED
- Temp files removed on error: VERIFIED
- Lock files released properly: VERIFIED
- No orphaned mount points: CONFIRMED

### Test Environment
- OS: Debian 13 (Trixie)
- HOMESERVER version: [version]
- Test setup: VM with LUKS partitions
- Services tested: [list services]

### Test Methodology
[Describe your testing approach and specific commands used]
```

## Commit Message Guidelines

Detailed, informative commit messages:

```
Improve LUKS unmounting reliability in unmountDrive.sh

Enhanced unmounting process to handle edge cases:
- Added retry logic with exponential backoff
- Check for open files before unmount (lsof)
- Graceful process termination before force unmount
- Better error messages indicating specific failure reasons
- Proper cleanup of device mapper resources

Changes made:
- unmountDrive.sh: Added pre-unmount checks and retry logic
- Added helper function check_open_files()
- Improved logging throughout unmount process

Testing:
- Tested normal unmount: SUCCESS
- Tested with open files: PROCESSES terminated, then unmounted
- Tested with busy mount: RETRIED successfully
- Tested cleanup after failure: RESOURCES released properly

Addresses issues seen when services hold file handles during unmount.
```

## Pull Request Process

### PR Description Template

```markdown
## Summary
Brief description of what this PR accomplishes.

## Motivation
Why is this change needed? What problem does it solve?

## Changes Made
- Specific change 1 with rationale
- Specific change 2 with rationale
- Specific change 3 with rationale

## Security Considerations
Any security implications? How were they addressed?

## Testing Performed
[Use comprehensive testing template above]

## Backward Compatibility
Does this affect existing installations? Migration needed?

## Documentation Updates
What documentation was updated or needs updating?

## Checklist
- [ ] Code follows shell/Python best practices
- [ ] Error handling is comprehensive
- [ ] Logging is appropriate and doesn't expose secrets
- [ ] File permissions are correct
- [ ] Cleanup handlers work properly
- [ ] Testing completed successfully
- [ ] Documentation updated
- [ ] No breaking changes (or documented if unavoidable)
```

### Review Process

1. **Code review**: Check for security, reliability, code quality
2. **Security analysis**: Evaluate security implications
3. **Testing**: Maintainer may perform independent testing
4. **Discussion**: Collaborate on any concerns or improvements
5. **Approval**: Merge after satisfactory review

Infrastructure changes require thorough review and may take longer.

## Architecture Understanding

### Component Overview

- **`init.sh`**: System initialization and service orchestration
- **`mountDrive.sh`**: LUKS encrypted drive mounting with systemd integration
- **`unmountDrive.sh`**: Safe drive unmounting and cleanup
- **`exportNAS.sh`**: Secure key management integration
- **`closeNAS.sh`**: Forced unmounting and cleanup
- **`transmission.py`**: VPN-isolated Transmission with network namespaces

### Integration Points

- **Keyman**: Secure credential retrieval for encrypted drives
- **Systemd**: Service management and boot-time initialization
- **LUKS**: Encrypted storage management
- **Network namespaces**: VPN isolation for specific services

### Security Model

- Scripts run with root privileges (necessary for mount/crypto operations)
- Minimize privilege duration
- Secure temp file handling
- Proper permission management (600/700 for sensitive files)
- Integration with HOMESERVER keyman for credential management

## Security Guidelines

### Critical Principles

1. **Privilege minimization**: Use root only when necessary
2. **Input validation**: Never trust user input or external data
3. **Secure defaults**: Default to most secure configuration
4. **Defense in depth**: Multiple layers of security
5. **Fail safely**: Errors should deny access, not grant it
6. **Audit trail**: Log security-relevant operations
7. **Least surprise**: Behavior should match expectations

### Common Pitfalls to Avoid

- Command injection through unsanitized input
- Race conditions in temp file handling
- Improper cleanup leaving system in inconsistent state
- Exposing sensitive data in logs or error messages
- Inadequate error handling leading to undefined state
- Not checking command return codes
- Hardcoding paths or credentials

## Getting Help

### Resources

- **Vault README**: Architecture and usage documentation
- **HOMESERVER docs**: Platform architecture and integration
- **Man pages**: `man cryptsetup`, `man systemd`, `man ip-netns`

### Questions?

- **Open an issue**: General contribution questions
- **Email**: Security or sensitive questions (owner@arpaservers.com)
- **Study existing code**: Learn patterns from current implementation

## Recognition

Contributors:
- Are credited in the repository
- Help maintain critical HOMESERVER infrastructure
- Build professional system administration portfolio
- May receive special recognition for significant contributions

## License

This project is licensed under **GPL-3.0**. Contributions are accepted under this license, and no CLA is required.

---

**Thank you for contributing to HOMESERVER infrastructure!**

These tools are the operational backbone of digital sovereignty. Your work directly enables secure, private infrastructure.

*HOMESERVER LLC - Professional Digital Sovereignty Solutions*

