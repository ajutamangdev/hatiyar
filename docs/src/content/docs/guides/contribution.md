---
title: Contributing Guidelines
description: How to contribute to hatiyar
---

Thank you for your interest in contributing to hatiyar! This guide will help you get started with contributing code, modules, documentation, and more.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment
- Report unacceptable behavior to maintainers

## Ways to Contribute

### 1. Report Bugs

Found a bug? Help us fix it!

**Before reporting:**
- Check existing issues to avoid duplicates
- Verify you're using the latest version
- Test with minimal configuration

**Good bug reports include:**
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Error messages or stack traces
- Screenshots if applicable


### 2. Suggest Features

Have an idea? We'd love to hear it!

**Feature requests should include:**
- Clear use case
- Expected behavior
- Example usage
- Why it's valuable

### 3. Contribute Code


#### Development Workflow

1. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

2. **Make changes:**
   - Follow code style guidelines (see below)
   - Add tests for new functionality
   - Update documentation
   ```

3. **Lint and format:**
   ```bash
   # Format code
   make format
   
   # Check style
   make lint
   # or
   uvx ruff check src/hatiyar
   ```

5. **Commit changes:**
   ```bash
   git add .
   git commit -m "feat: add new CVE module for ..."
   ```

6. **Push and create PR:**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then open a Pull Request on GitHub.

#### Commit Message Convention

Follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(cve): add CVE-2024-12345 exploit module
fix(shell): resolve command parsing issue
docs(readme): update installation instructions
test(modules): add tests for module loading
```

### 4. Add New Modules

#### Module Development Process

**1. Plan your module:**
- Identify the vulnerability/feature
- Define required options
- Determine expected behavior

**2. Create module file:**

```python
# src/hatiyar/modules/cve/your-custom-exploit.py
from hatiyar.core.module_base import CVEModule

class Module(ModuleBase):
    """
    CVE-2024-12345 - Vulnerability Name
    
    Description of what this module does.
    Affected versions: X.X.X - Y.Y.Y
    Patched versions: Z.Z.Z+
    """
    
    NAME = "CVE-2024-12345 Exploit"
    DESCRIPTION = "Brief description of exploit"
    CATEGORY = "cve"
    CVE = "CVE-2024-12345"
    AUTHOR = "Your Name"
    
    OPTIONS = {
        "RHOST": "",
        "RPORT": 80,
        "TIMEOUT": 10,
    }
    
    REQUIRED_OPTIONS = ["RHOST"]
    
    def run(self):
        """Execute the exploit"""
        rhost = self.options["RHOST"]
        rport = self.options["RPORT"]
        
        self.info(f"Targeting {rhost}:{rport}")
        
        try:
            # Your exploit logic here
            result = self.exploit()
            
            if result:
                self.success("Exploitation successful!")
                self.info(f"Result: {result}")
            else:
                self.error("Exploitation failed")
                
        except Exception as e:
            self.error(f"Error: {e}")
    
    def exploit(self):
        """Implement exploit logic"""
        # Implementation here
        pass
```

**3. Register module:**

```yaml
# src/hatiyar/modules/cve/cve.yaml
modules:
  - id: CVE-2024-12345
    name: "CVE-2024-12345 - Vulnerability Name"
    module_path: "cve.2024.cve_2024_12345"
    category: "cve"
    cve_id: "CVE-2024-12345"
    description: "Brief description"
    author: "Your Name"
```

**4. Add tests:**

```python
# tests/test_cve_2024_12345.py
import pytest
from hatiyar.core.modules import ModuleRegistry

def test_module_loads():
    """Test module can be loaded"""
    registry = ModuleRegistry()
    module = registry.get_module("CVE-2024-12345")
    assert module is not None

def test_required_options():
    """Test required options validation"""
    registry = ModuleRegistry()
    module = registry.get_module("CVE-2024-12345")
    
    # Should fail without RHOST
    with pytest.raises(ValueError):
        module.validate_options()
    
    # Should pass with RHOST
    module.set_option("RHOST", "target.com")
    module.validate_options()

def test_exploit_logic():
    """Test exploit functionality"""
    # Add specific tests for your exploit logic
    pass
```

#### Module Best Practices

**Security:**
- Validate all inputs
- Handle errors gracefully
- Don't hardcode credentials
- Use timeouts for network operations
- Respect SSL verification options

**Code Quality:**
- Add docstrings
- Use type hints
- Follow PEP 8 style guide
- Keep functions small and focused
- Add comprehensive error handling

**User Experience:**
- Provide clear status messages
- Use `self.info()`, `self.success()`, `self.error()`
- Show progress for long operations
- Give helpful error messages

**Testing:**
- Test success path
- Test error cases
- Test option validation
- Mock external dependencies
- Test edge cases

### 5. Improve Documentation

Documentation is crucial! You can help by:

- Fixing typos and grammar
- Adding examples
- Clarifying confusing sections
- Creating tutorials
- Adding screenshots
- Translating docs

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No sensitive data in commits

### Review Process

1. CI/CD checks run
2. Maintainer reviews code
3. Feedback provided if needed
4. Approved and merged

## Community

### Getting Help

 - [GitHub Issues](https://github.com/ajutamangdev/hatiyar/issues): Bug reports and feature requests
 - [Discussions](https://github.com/ajutamangdev/hatiyar/discussions): Questions and general discussion

## Questions?

Don't hesitate to ask! Create an issue labeled "question" or reach out to maintainers.

Thank you for contributing to hatiyar!
