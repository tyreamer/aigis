"""Custom/generic tool and approval patterns."""

# Decorator names that indicate approval (substring match, case-insensitive)
APPROVAL_DECORATOR_PATTERNS = {
    "requires_approval", "approval", "approve", "confirm",
    "consent", "authorize", "human_approval", "gate", "policy",
    "human_in_the_loop",
}

# Stricter subset: consent/policy wrappers (for AEG002)
CONSENT_DECORATOR_PATTERNS = {
    "policy", "consent", "requires_consent", "requires_policy",
    "privileged_check", "elevated_check",
}

# Function call names that register tools (substring match)
TOOL_REGISTRATION_NAME_PATTERNS = {"register", "tool"}
