"""Lab 11 — Configuration & API Key Setup."""
from __future__ import annotations

import getpass
import os
from pathlib import Path


def _load_project_env() -> None:
    """Load .env from the repository root regardless of current directory."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env", override=False)


def setup_api_key() -> None:
    """Load OpenAI API key from .env/environment or securely prompt once."""
    _load_project_env()
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        key = getpass.getpass("Enter OpenAI API Key: ").strip()
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY is missing. Create a .env file in the project root."
            )
        os.environ["OPENAI_API_KEY"] = key
    print("API key loaded.")


ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer", "loan", "interest",
    "savings", "credit", "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat", "chuyen tien",
    "the tin dung", "so du", "vay", "ngan hang", "atm",
    "tài khoản", "giao dịch", "tiết kiệm", "lãi suất", "chuyển tiền",
    "thẻ tín dụng", "số dư", "vay vốn", "ngân hàng", "phí", "hạn mức",
]

BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal", "violence",
    "gambling", "bomb", "kill", "steal",
]
