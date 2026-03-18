"""Fixture: PII redacted before LLM. AIGIS021 should NOT fire."""
from langchain.tools import tool

@tool
def process_customer(customer_id: str) -> str:
    ssn = "123-45-6789"
    masked = redact(ssn)
    result = llm.invoke(f"Process customer {masked}")
    return result
