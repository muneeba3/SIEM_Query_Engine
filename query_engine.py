import json
import re
import os
import pandas as pd
from datetime import datetime, timezone


def load_logs(filepath):
    with open(filepath) as f:
        return pd.DataFrame(json.load(f))


def run_query(df, query):
    """
    SPL-inspired query engine.
    Supports:
      search <term>
      where <field>=<value>
      filter severity=<level>
      stats count by <field>
      sort <field>
      head <n>
    """
    result = df.copy()
    query = query.strip()

    # search keyword (free text across all fields)
    search_match = re.match(r'search\s+"?([^"]+)"?', query, re.IGNORECASE)
    if search_match:
        term = search_match.group(1).lower()
        result = result[result.apply(
            lambda row: term in str(row.values).lower(), axis=1)]
        return result

    # where field=value
    where_match = re.match(r'where\s+(\w+)\s*=\s*"?([^"]+)"?',
                            query, re.IGNORECASE)
    if where_match:
        field, value = where_match.group(1), where_match.group(2)
        if field in result.columns:
            result = result[result[field].astype(str).str.lower()
                           == value.lower()]
        return result

    # filter severity=<level>
    filter_match = re.match(r'filter\s+severity\s*=\s*(\w+)',
                             query, re.IGNORECASE)
    if filter_match:
        sev = filter_match.group(1).lower()
        result = result[result["severity"] == sev]
        return result

    # stats count by field
    stats_match = re.match(r'stats\s+count\s+by\s+(\w+)',
                            query, re.IGNORECASE)
    if stats_match:
        field = stats_match.group(1)
        if field in result.columns:
            return result.groupby(field).size().reset_index(
                name="count").sort_values("count", ascending=False)

    # head n
    head_match = re.match(r'head\s+(\d+)', query, re.IGNORECASE)
    if head_match:
        return result.head(int(head_match.group(1)))

    # sort field
    sort_match = re.match(r'sort\s+(\w+)', query, re.IGNORECASE)
    if sort_match:
        field = sort_match.group(1)
        if field in result.columns:
            return result.sort_values(field, ascending=False)

    print("Unknown command. Try: search, where, filter, stats count by, head, sort")
    return result


def save_result(result, query):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    safe_query = re.sub(r'[^a-zA-Z0-9]', '_', query[:30]).strip('_')
    outfile = f"output/{timestamp}_{safe_query}.json"
    result.to_json(outfile, orient="records", indent=2)
    return outfile


def print_help():
    print("""
Available commands:
  search <term>              Search all fields for a keyword
  where <field>=<value>      Filter by exact field value
  filter severity=<level>    Filter by severity (low/medium/high/critical)
  stats count by <field>     Count events grouped by field
  sort <field>               Sort results by field descending
  head <n>                   Show first N results
  help                       Show this help
  exit                       Quit

Examples:
  siem> filter severity=critical
  siem> where event_id=4625
  siem> stats count by user
  siem> search powershell
  siem> where host=DC-01
  siem> head 20
""")


def interactive_mode(df):
    print(f"\nSIEM Query Engine — {len(df)} events loaded")
    print("Type 'help' for commands or 'exit' to quit\n")

    while True:
        try:
            query = input("siem> ").strip()

            if not query:
                continue
            if query.lower() == "exit":
                print("Goodbye.")
                break
            if query.lower() == "help":
                print_help()
                continue

            result = run_query(df, query)

            if result.empty:
                print("No results found.\n")
                continue

            print(f"\n{result.to_string(index=False)}")
            print(f"\n{len(result)} result(s)")

            outfile = save_result(result, query)
            print(f"Saved → {outfile}\n")

        except KeyboardInterrupt:
            print("\nGoodbye.")
            break
        except Exception as e:
            print(f"Error: {e}\n")


if __name__ == "__main__":
    df = load_logs("logs/windows_events.json")
    interactive_mode(df)