import os
import json
import pandas as pd

ROOT_BENCHMARK = "target/criterion"

def compute_table(system, operation):
    base = f"{ROOT_BENCHMARK}/{operation}_{system}"
    records = []

    for root, dirs, files in os.walk(base):
        if "estimates.json" in files:
            bench_name = os.path.relpath(root, base)

            # Only keep benchmarks that end with "new"
            if not bench_name.endswith("base"):
                continue

            # Remove the trailing "/new"
            clean_name = bench_name.rsplit("/base", 1)[0]

            path = os.path.join(root, "estimates.json")
            with open(path) as f:
                data = json.load(f)
                mean_ns = data["mean"]["point_estimate"]
                mean_ms = mean_ns / 1e6  # convert to milliseconds

            if system == "cgka":
                # Format: "<user> - <n_users>"
                user, n_users = clean_name.split(" - ")
                records.append({
                    "user": user,
                    "n_users": int(n_users),
                    "mean_ms": mean_ms
                })

            elif system == "sumac":
                # Format: "<user>_<n_admins>-<n_users>"
                print(clean_name)
                user, tup = clean_name.split("_")
                n_admins, n_users = tup.split("-")
                records.append({
                    "user": user,
                    "n_admins": int(n_admins),
                    "n_users": int(n_users),
                    "mean_ms": mean_ms
                })

    # Build dataframe and pivot
    df = pd.DataFrame(records)

    if system == "cgka":
        table = df.pivot(index="n_users", columns="user", values="mean_ms").sort_index()
    else:  # sumac
        table = df.pivot(index=["n_admins", "n_users"], columns="user", values="mean_ms").sort_index()

    # Show results
    print(f"\n=== {system} / {operation} ===")
    print(table)

    # Export to LaTeX
    with open(f"table_{system}_{operation}.tex", "w") as f:
        f.write(table.to_latex(float_format="%.2f"))

BENCHES = {
    "cgka": ["add-user", "remove-user", "update-user"],
    "sumac": ["add-admin", "add-user", "remove-user", "update-user"]
}

if __name__ == "__main__":
    for system, operations in BENCHES.items():
        for operation in operations:
            compute_table(system, operation)
