import click
from .commands import (init_cmd, add_cmd, keygen_cmd, commit_cmd, branch_cmd,
                       remote_cmd, push_cmd, adduser_cmd, clone_cmd, pull_cmd,
                       ignore_cmd, newrepo_cmd, checkout_cmd, merge_cmd)

@click.group()
def cli():
    """SecureGit - Secure Git repository encryption tool."""
    pass

cli.add_command(init_cmd.securegit_init, name="init")

cli.add_command(add_cmd.securegit_add, name="add")

cli.add_command(commit_cmd.securegit_commit, name="commit")

cli.add_command(keygen_cmd.generate_keys, name="keygen")

cli.add_command(branch_cmd.securegit_branch, name="branch")

cli.add_command(remote_cmd.securegit_remote, name="remote")

cli.add_command(push_cmd.securegit_push, name="push")

cli.add_command(adduser_cmd.securegit_adduser, name="adduser")

cli.add_command(clone_cmd.securegit_clone, name="clone")

cli.add_command(pull_cmd.securegit_pull, name="pull")

cli.add_command(ignore_cmd.secure_ignore, name="ignore")

cli.add_command(newrepo_cmd.securegit_newrepo, name="newrepo")

cli.add_command(checkout_cmd.securegit_checkout, name="checkout")

cli.add_command(merge_cmd.securegit_merge, name="merge")

if __name__ == "__main__":
    cli()