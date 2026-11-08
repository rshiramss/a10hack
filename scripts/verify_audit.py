"""Walk the audit hash chain and report the first broken link.

Usage: uv run python -m scripts.verify_audit [--db data/badge.db]
Exit code 0 when the chain verifies, 1 when it is broken.
"""

from __future__ import annotations

import argparse
import sys

from badge import db
from badge.audit import verify_chain


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default="data/badge.db")
    args = parser.parse_args()
    conn = db.connect(args.db)
    try:
        report = verify_chain(conn)
    finally:
        conn.close()
    if report.ok:
        print(f"chain verified: {report.rows_checked} rows")
        return 0
    print(
        f"chain BROKEN at seq {report.first_bad_seq}"
        f" ({report.rows_checked} rows verified before it)"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
