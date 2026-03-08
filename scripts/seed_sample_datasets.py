"""
Seed sample datasets for demonstration and testing.

Creates high-quality example datasets that demonstrate:
1. Customer support fine-tuning
2. Code generation fine-tuning
3. Content moderation fine-tuning
4. FAQ answering fine-tuning

Usage:
    python scripts/seed_sample_datasets.py
"""

import asyncio
import importlib
import sys
from pathlib import Path


def _load_runtime_symbols():
    """Load runtime dependencies while keeping this script directly executable."""
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    models = importlib.import_module("server.models")
    sqlmodel_module = importlib.import_module("sqlmodel")
    return (
        models.Dataset,
        models.TestCase,
        models.TestCaseStatus,
        models.get_session,
        sqlmodel_module.select,
    )


(
    DATASET_MODEL,
    TEST_CASE_MODEL,
    TEST_CASE_STATUS,
    get_session,
    select,
) = _load_runtime_symbols()


# Sample datasets with real-world examples
SAMPLE_DATASETS = [
    {
        "name": "Customer Support - E-commerce",
        "description": (
            "Fine-tuning dataset for e-commerce customer support bot. "
            "Covers order status, returns, shipping, and product questions."
        ),
        "test_cases": [
            {
                "name": "order_status_inquiry",
                "tool": "chat",
                "inputs": {"message": "Where is my order #12345?"},
                "expected_output": {
                    "response": (
                        "I'll help you track your order! Order #12345 was shipped "
                        "on January 5th and is currently in transit. Expected "
                        "delivery is January 10th. You can track it using tracking "
                        "number TRK123456789."
                    )
                },
                "tags": ["order_tracking", "customer_service"],
            },
            {
                "name": "return_request",
                "tool": "chat",
                "inputs": {"message": "I want to return a product I bought last week"},
                "expected_output": {
                    "response": (
                        "I can help you with that return! Our return policy allows "
                        "returns within 30 days of purchase. To process your return:\n"
                        "1. Go to 'My Orders' in your account\n"
                        "2. Select the item you want to return\n"
                        "3. Choose your return reason\n"
                        "4. Print the prepaid return label\n"
                        "5. Drop it off at any shipping location\n"
                        "You'll receive your refund within 5-7 business days after "
                        "we receive the item."
                    )
                },
                "tags": ["returns", "customer_service"],
            },
            {
                "name": "product_availability",
                "tool": "chat",
                "inputs": {"message": "Do you have the XYZ laptop in stock?"},
                "expected_output": {
                    "response": (
                        "Yes, the XYZ laptop is currently in stock! We have 15 units "
                        "available. It's priced at $999 with free shipping. Would you "
                        "like me to add it to your cart?"
                    )
                },
                "tags": ["product_inquiry", "inventory"],
            },
            {
                "name": "shipping_cost_question",
                "tool": "chat",
                "inputs": {"message": "How much is shipping to California?"},
                "expected_output": {
                    "response": (
                        "Shipping to California costs:\n"
                        "- Standard (5-7 days): $5.99\n"
                        "- Express (2-3 days): $12.99\n"
                        "- Overnight: $24.99\n"
                        "FREE standard shipping on orders over $50!"
                    )
                },
                "tags": ["shipping", "pricing"],
            },
            {
                "name": "password_reset",
                "tool": "chat",
                "inputs": {"message": "I forgot my password"},
                "expected_output": {
                    "response": (
                        "No problem! I can help you reset your password:\n"
                        "1. Click the 'Forgot Password' link on the login page\n"
                        "2. Enter your email address\n"
                        "3. Check your email for a password reset link "
                        "(check spam folder too!)\n"
                        "4. Click the link and create a new password\n"
                        "The reset link is valid for 1 hour. Let me know if you "
                        "don't receive the email!"
                    )
                },
                "tags": ["account_management", "password"],
            },
        ],
    },
    {
        "name": "Code Generation - Python",
        "description": (
            "Dataset for fine-tuning code generation models on Python programming "
            "tasks. Includes functions, classes, and algorithms."
        ),
        "test_cases": [
            {
                "name": "fibonacci_function",
                "tool": "code_gen",
                "inputs": {
                    "prompt": "Write a Python function to calculate the nth Fibonacci number"
                },
                "expected_output": {
                    "code": """def fibonacci(n: int) -> int:
    \"\"\"Calculate the nth Fibonacci number.

    Args:
        n: Position in Fibonacci sequence (0-indexed)

    Returns:
        The nth Fibonacci number
    \"\"\"
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)"""
                },
                "tags": ["algorithms", "recursion"],
            },
            {
                "name": "binary_search",
                "tool": "code_gen",
                "inputs": {"prompt": "Implement binary search in Python"},
                "expected_output": {
                    "code": """def binary_search(arr: list[int], target: int) -> int:
    \"\"\"Search for target in sorted array using binary search.

    Args:
        arr: Sorted list of integers
        target: Value to search for

    Returns:
        Index of target if found, -1 otherwise
    \"\"\"
    left, right = 0, len(arr) - 1

    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1

    return -1"""
                },
                "tags": ["algorithms", "search"],
            },
            {
                "name": "class_definition",
                "tool": "code_gen",
                "inputs": {
                    "prompt": (
                        "Create a Python class for a bank account with deposit and withdraw methods"
                    )
                },
                "expected_output": {
                    "code": """class BankAccount:
    \"\"\"A simple bank account class.\"\"\"

    def __init__(self, account_number: str, initial_balance: float = 0.0):
        self.account_number = account_number
        self.balance = initial_balance

    def deposit(self, amount: float) -> float:
        \"\"\"Deposit money into the account.\"\"\"
        if amount <= 0:
            raise ValueError(\"Deposit amount must be positive\")
        self.balance += amount
        return self.balance

    def withdraw(self, amount: float) -> float:
        \"\"\"Withdraw money from the account.\"\"\"
        if amount <= 0:
            raise ValueError(\"Withdrawal amount must be positive\")
        if amount > self.balance:
            raise ValueError(\"Insufficient funds\")
        self.balance -= amount
        return self.balance

    def get_balance(self) -> float:
        \"\"\"Get current account balance.\"\"\"
        return self.balance"""
                },
                "tags": ["oop", "classes"],
            },
        ],
    },
    {
        "name": "Content Moderation",
        "description": (
            "Training data for content moderation classifier. Identifies toxic, "
            "spam, or inappropriate content."
        ),
        "test_cases": [
            {
                "name": "professional_content",
                "tool": "moderate",
                "inputs": {
                    "text": (
                        "Thank you for the helpful response! This really clarified things for me."
                    )
                },
                "expected_output": {
                    "classification": "safe",
                    "confidence": 0.98,
                    "reason": "Polite, professional, and constructive content",
                },
                "tags": ["safe", "professional"],
            },
            {
                "name": "spam_detection",
                "tool": "moderate",
                "inputs": {"text": "CLICK HERE NOW!!! WIN $1000000 FREE!!! LIMITED TIME!!!"},
                "expected_output": {
                    "classification": "spam",
                    "confidence": 0.95,
                    "reason": (
                        "Contains spam indicators: excessive caps, unrealistic promises, urgency"
                    ),
                },
                "tags": ["spam", "promotional"],
            },
            {
                "name": "technical_discussion",
                "tool": "moderate",
                "inputs": {
                    "text": (
                        "The algorithm has O(n log n) time complexity but "
                        "uses O(n) space. We could optimize memory usage by "
                        "using an in-place sort."
                    )
                },
                "expected_output": {
                    "classification": "safe",
                    "confidence": 0.99,
                    "reason": "Technical discussion, educational content",
                },
                "tags": ["safe", "technical"],
            },
        ],
    },
    {
        "name": "FAQ - Product Documentation",
        "description": (
            "Question-answer pairs for product documentation assistant. "
            "Trained to answer common product questions accurately."
        ),
        "test_cases": [
            {
                "name": "installation_question",
                "tool": "faq",
                "inputs": {"question": "How do I install the software?"},
                "expected_output": {
                    "answer": (
                        "To install the software:\n"
                        "1. Download the installer from our website\n"
                        "2. Run the installer executable\n"
                        "3. Follow the on-screen instructions\n"
                        "4. Restart your computer when prompted\n"
                        "5. Launch the application from your Start Menu or "
                        "Applications folder\n\n"
                        "System requirements:\n"
                        "- Windows 10/11 or macOS 12+\n"
                        "- 8GB RAM minimum (16GB recommended)\n"
                        "- 2GB free disk space"
                    )
                },
                "tags": ["installation", "setup"],
            },
            {
                "name": "pricing_question",
                "tool": "faq",
                "inputs": {"question": "What are the pricing plans?"},
                "expected_output": {
                    "answer": (
                        "We offer three pricing plans:\n\n"
                        "**Free Plan** - $0/month\n"
                        "- 100 API calls/day\n"
                        "- Community support\n"
                        "- Basic features\n\n"
                        "**Pro Plan** - $29/month\n"
                        "- 10,000 API calls/day\n"
                        "- Email support\n"
                        "- All features\n"
                        "- Custom integrations\n\n"
                        "**Enterprise Plan** - Custom pricing\n"
                        "- Unlimited API calls\n"
                        "- 24/7 phone support\n"
                        "- Dedicated account manager\n"
                        "- SLA guarantee\n"
                        "- Custom deployment options"
                    )
                },
                "tags": ["pricing", "plans"],
            },
            {
                "name": "api_authentication",
                "tool": "faq",
                "inputs": {"question": "How do I authenticate API requests?"},
                "expected_output": {
                    "answer": (
                        "API authentication uses Bearer tokens:\n\n"
                        "1. Generate an API key in your dashboard "
                        "(Settings > API Keys)\n"
                        "2. Include the key in your request headers:\n"
                        "   ```\n"
                        "   Authorization: Bearer YOUR_API_KEY\n"
                        "   ```\n"
                        "3. Example request:\n"
                        "   ```bash\n"
                        '   curl -H "Authorization: Bearer sk_your_key" \\\n'
                        "        https://api.example.com/v1/endpoint\n"
                        "   ```\n\n"
                        "**Security tips:**\n"
                        "- Never commit API keys to version control\n"
                        "- Rotate keys regularly\n"
                        "- Use different keys for development and production\n"
                        "- Revoke compromised keys immediately"
                    )
                },
                "tags": ["api", "authentication", "security"],
            },
        ],
    },
]


async def seed_datasets():
    """Create sample datasets in the database."""
    print("[SEEDING] Seeding sample datasets...")
    print()

    async for session in get_session():
        try:
            for dataset_data in SAMPLE_DATASETS:
                # Check if dataset already exists
                stmt = select(DATASET_MODEL).where(DATASET_MODEL.name == dataset_data["name"])
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()

                if existing:
                    print(f"[SKIP] Dataset '{dataset_data['name']}' already exists, skipping...")
                    continue

                # Create dataset
                dataset = DATASET_MODEL(
                    name=dataset_data["name"],
                    description=dataset_data["description"],
                    created_by_user_id=1,  # Admin user
                )
                session.add(dataset)
                await session.flush()  # Get the dataset ID

                print(f" Created dataset: {dataset.name}")

                # Add test cases
                for tc_data in dataset_data["test_cases"]:
                    test_case = TEST_CASE_MODEL(
                        dataset_id=dataset.id,
                        name=tc_data["name"],
                        tool=tc_data["tool"],
                        inputs=tc_data["inputs"],
                        expected_output=tc_data["expected_output"],
                        tags=tc_data.get("tags", []),
                        status=TEST_CASE_STATUS.ACTIVE,
                    )
                    session.add(test_case)

                print(f"   Added {len(dataset_data['test_cases'])} test cases")
                print()

            await session.commit()
            print("[DONE] Sample datasets seeded successfully!")
            print()
            print("You can now:")
            print("  1. View datasets: http://localhost:3000/datasets")
            print("  2. Export for fine-tuning: GET /api/datasets/{id}/export/finetune")
            print("  3. Run test cases: POST /api/datasets/{id}/test-runs")

        except Exception as e:
            await session.rollback()
            print(f" Error seeding datasets: {e}")
            raise


if __name__ == "__main__":
    print()
    print("=" * 80)
    print("AgentGate Sample Dataset Seeder")
    print("=" * 80)
    print()

    try:
        asyncio.run(seed_datasets())
    except KeyboardInterrupt:
        print("\n\n  Seeding interrupted by user")
    except (OSError, RuntimeError, ValueError) as e:
        print(f"\n\n Error: {e}")
        sys.exit(1)
