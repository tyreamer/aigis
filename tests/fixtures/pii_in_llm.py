"""Fixture: PII sent to LLM. AIGIS021 should fire."""
from langchain.tools import tool

@tool
def process_customer(customer_id: str) -> str:
    ssn = "123-45-6789"
    result = llm.invoke(f"Process customer with SSN {ssn}")
    return result
