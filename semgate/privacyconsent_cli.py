"""Operator-only consent commands, guarded like other semgate administration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import adminguard, trustauth
from .privacyconsent import ConsentStore


def command(args: argparse.Namespace) -> int:
    weakening = [f"Approve disclosure consent {args.id} for the displayed scope.",
                 "It is reusable until expiry or task completion; revocation stops future sends."] if args.action == "approve" else []
    code = adminguard.guard("consent " + args.action, weakening=weakening)
    if code:
        return code
    try:
        store = ConsentStore(Path(args.store))
        auth = trustauth.Auth("terminal")
        if args.action == "approve":
            store.approve(args.id, auth=auth, task_scope=not args.snapshot,
                          ttl_s=None if args.ttl_hours is None else args.ttl_hours * 3600)
        elif args.action == "revoke":
            store.revoke(args.id, auth=auth)
        else:
            store.close_task_of(args.id, auth=auth)
    except Exception as exc:
        print(f"semgate consent: operation failed ({type(exc).__name__}); no success confirmed", file=sys.stderr)
        return 2
    print(json.dumps({"consent_id": args.id, "action": args.action}))
    return 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("consent", help="Operator-only task disclosure consent; never run this for the agent")
    parser.add_argument("action", choices=("approve", "revoke", "close-task"))
    parser.add_argument("id", help="Request/grant id shown with the disclosure scope")
    parser.add_argument("--store", required=True, help="Protected consent store used by the embedding application")
    parser.add_argument("--ttl-hours", type=float, default=None, help="Approval lifetime, bounded by the requesting host (at most 4h)")
    parser.add_argument("--snapshot", action="store_true", help="Approve only this payload snapshot instead of the current task scope")
    parser.set_defaults(func=command)
