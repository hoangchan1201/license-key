"""Admin utility for the DewTool License API; keep its token private."""
import argparse
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def call(base, token, path, method="GET", data=None):
    headers = {"Authorization": f"Bearer {token}"}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(base.rstrip("/") + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        raise SystemExit(1)
    except URLError as exc:
        print(f"Could not reach License API: {exc}", file=sys.stderr)
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description="Manage DewTool license keys")
    parser.add_argument("command", choices=("create", "list", "revoke", "reset"))
    parser.add_argument("--days", type=int, help="license duration on first activation")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--key", help="key to revoke or reset")
    parser.add_argument("--url", default=os.environ.get("LICENSE_API_BASE_URL", ""))
    args = parser.parse_args()
    token = os.environ.get("LICENSE_ADMIN_TOKEN", "")
    if not args.url or not token:
        parser.error("set LICENSE_API_BASE_URL and LICENSE_ADMIN_TOKEN environment variables")

    if args.command == "create":
        if not args.days:
            parser.error("create requires --days")
        result = call(args.url, token, "/api/v1/admin/licenses", "POST", {"days": args.days, "count": args.count})
        print("Copy and save these keys now; the server stores only their hashes:")
        for key in result["keys"]:
            print(key)
    elif args.command == "list":
        result = call(args.url, token, "/api/v1/admin/licenses")
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        if not args.key:
            parser.error(f"{args.command} requires --key")
        path = "/api/v1/admin/" + args.command
        result = call(args.url, token, path, "POST", {"key": args.key})
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
