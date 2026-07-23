import click
import subprocess

@click.command(context_settings=dict(allow_interspersed_args=False))
@click.argument("encrypted_repo_path")
@click.argument("push_args", nargs=-1)  # capture all git push args
def securegit_push(encrypted_repo_path, push_args):
    """
    securegit push <encrypted_repo_path> [git push args...]
    Push changes in the encrypted repository and print all output, including 'Everything up-to-date'.
    """
    # Build git push command
    cmd = ["git", "-C", encrypted_repo_path, "push"] + list(push_args)

    try:
        # Run the command and stream output directly to terminal
        print("[+] Encrypted repo push result:")
        process = subprocess.run(cmd, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Git push failed with exit code {e.returncode}")
