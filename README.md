# Org AWS IAM Role for Emacs

`org-aws-iam-role.el` is an Emacs package for inspecting **and modifying** AWS IAM roles and their policy documents. It renders all role data—including trust policies, permissions boundaries, and all associated policies (AWS managed, customer managed, and inline)—in an interactive Org-mode buffer. It also includes a powerful IAM policy simulator to test a role's permissions against specific actions and resources directly within Emacs.

This package uses Org Babel and the AWS CLI under the hood, allowing you to edit policies directly in the buffer and apply them to your AWS account. All initial policy data is fetched **asynchronously and in parallel**.

-----

## Demonstration

[![Org AWS IAM Role for Emacs Demo](https://img.youtube.com/vi/9HffiDAg10U/hqdefault.jpg)](https://youtu.be/9HffiDAg10U)

-----

## Features

  * **Browse and Inspect IAM Roles** via an interactive prompt.
  * **Modify IAM Policies**: Edit policies directly in the Org buffer and apply changes by executing the source block (`C-c C-c`).
      * Supports Trust Policies, Permissions Boundaries, Customer-Managed, AWS-Managed, and Inline policies.
  * **IAM Policy Simulator**: Test the role's permissions against a list of actions and resources using `iam:SimulatePrincipalPolicy` (`C-c C-s`).
  * **Read-Only by Default**: Buffers open in a safe, read-only mode to prevent accidental changes. Toggle editing with a keypress.
  * **Org Babel Integration** using a custom `aws-iam` language for applying changes.
  * **Asynchronous Parallel Fetching** for fast initial loading of all policies.
  * **Org-mode Rendering** with foldable sections for easy navigation.
  * **Switch AWS CLI profiles** interactively.
  * **Authenticates via CLI** and alerts on credential issues before running commands.

-----

## Requirements

  * **GNU Emacs 29.1+**
  * AWS CLI installed and in your `PATH`
  * Permissions for the following AWS IAM APIs:
      * `sts:GetCallerIdentity`
      * `iam:GetRole`
      * `iam:ListRoles`
      * `iam:ListAttachedRolePolicies`
      * `iam:ListRolePolicies`
      * `iam:GetPolicy`
      * `iam:GetPolicyVersion`
      * `iam:GetRolePolicy`
      * `iam:UpdateAssumeRolePolicy` (to modify trust policies)
      * `iam:PutRolePolicy` (to modify inline policies)
      * `iam:CreatePolicyVersion` (to modify managed policies)
      * `iam:SimulatePrincipalPolicy` (for the policy simulator)

Emacs libraries used: `cl-lib`, `json`, `url-util`, `async`, `promise`, `ob-shell`.

-----

## Usage

1.  Load the package (e.g. `(require 'org-aws-iam-role)`)
2.  Run:
    `M-x org-aws-iam-role-view-details`
3.  Select a role from the list.
4.  The buffer will open in read-only mode. To make changes:
    a.  Press `C-c C-e` to toggle editable mode.
    b.  Modify the JSON inside any policy's source block.
    c.  Press `C-c C-c` inside the block to apply the changes to AWS.
    d.  View the success or failure message in the `#+RESULTS:` block that appears.
5.  To test the role's effective permissions, press `C-c C-s` at any time to open the IAM policy simulator.

### Org Buffer Keybindings

| Keybinding | Description |
| :--- | :--- |
| `C-c C-e` | Toggle read-only mode to allow/prevent edits. |
| `C-c C-s` | Simulate the role's policies against specific actions. |
| `C-c C-c` | Inside a source block, apply changes to AWS. |
| `C-c (` | Hide all property drawers. |
| `C-c )` | Reveal all property drawers. |

-----

## Configuration

Optional variables for customizing behavior:

```elisp
(setq org-aws-iam-role-profile "my-profile") ;; Use a specific AWS CLI profile
(setq org-aws-iam-role-read-only-by-default t) ;; Open buffers in read-only mode
(setq org-aws-iam-role-show-folded-by-default t) ;; Show Org buffer folded by default
(setq org-aws-iam-role-fullscreen nil) ;; Prevent the buffer from taking the full frame
```

To change the profile at runtime, you can run:
`M-x org-aws-iam-role-set-profile`
