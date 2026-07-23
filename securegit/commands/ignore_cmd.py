import os
import click
from git import Repo

@click.command()
@click.argument("plaintext_repo_path", required=True)
@click.argument("encrypted_repo_path", required=True)
@click.argument("patterns", nargs=-1)
def secure_ignore(plaintext_repo_path, encrypted_repo_path, patterns):
    """
    Secure version of git ignore: create or update .gitignore
    in both plaintext and encrypted repositories.
    """

    if not patterns:
        raise click.UsageError("No ignore patterns provided. Please specify files/patterns to ignore.")

    repos = [plaintext_repo_path, encrypted_repo_path]

    for repo_path in repos:
        gitignore_path = os.path.join(repo_path, ".gitignore")


        existing_patterns = set()
        if os.path.exists(gitignore_path):
            with open(gitignore_path, "r", encoding="utf-8") as f:
                existing_patterns = set(
                    line.strip() for line in f if line.strip()
                )


        new_patterns = [p for p in patterns if p not in existing_patterns]
        if new_patterns:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                for p in new_patterns:
                    f.write(p + "\n")
            print(f"[+] Updated {gitignore_path} with: {new_patterns}")
        else:
            print(f"[=] No new patterns added to {gitignore_path} (already present).")


    for repo_path in repos:
        repo = Repo(repo_path)
        repo.git.add(".gitignore")
        print(f"[+] .gitignore staged in {repo_path}")
