import click
import json
import urllib.request
import urllib.error


@click.command(name="newrepo")
@click.argument("repo_name")
@click.option("--private", is_flag=True, help="Create a private repository (default is public).")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub Personal Access Token (or set env GITHUB_TOKEN).")
def securegit_newrepo(repo_name, private, token):
    """
    Create a new GitHub repository under your account.

    Example:
        securegit newrepo my-encrypted-repo --private --description "Secure repo"
    """
    if not token:
        click.echo("[!] GitHub token is required. Use --token or set GITHUB_TOKEN env variable.")
        return

    url = "https://api.github.com/user/repos"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "securegit-client"
    }
    payload = json.dumps({
        "name": repo_name,
        "private": private,
        "auto_init": False
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            repo_url = data.get("html_url")
            click.echo(f"[✓] Repository created successfully: {repo_url}")
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        click.echo(f"[!] Failed to create repository: {e.code}")
        click.echo(err)
