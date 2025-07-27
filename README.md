# IAM Role Viewer for Emacs

`aws-iam-role-viewer.el` is an Emacs package for inspecting AWS IAM roles and viewing its policy documents. It renders all role data—including trust policies, permissions boundaries, and all associated policies (AWS managed, customer managed, and inline)—in an Org-mode buffer using the AWS CLI under the hood.

All policy data is fetched **asynchronously and in parallel**, resulting in faster load times than previous version.

-----

## Features

  * **Inspect IAM Roles** via an interactive prompt.
  * **Asynchronous Parallel Fetching** for faster loading of all policies.
  * **Displays**:
      * Trust policy
      * Permissions boundary
      * Customer-managed policies
      * AWS-managed policies
      * Inline policies
  * **Org-mode Rendering** with foldable sections for easy navigation.
  * **Switch AWS CLI profiles** interactively.
  * **Authenticates via CLI** and alerts on credential issues before running commands.

-----

## Requirements

  * GNU Emacs 27+
  * AWS CLI installed and in your `PATH`
  * Permissions for the following AWS IAM APIs:
      * `get-role`
      * `list-roles`
      * `list-attached-role-policies`
      * `list-role-policies`
      * `get-policy`
      * `get-policy-version`
      * `get-role-policy`
      * `sts get-caller-identity`

Emacs libraries used: `cl-lib`, `json`, `url-util`, `async`, `promise`.

-----

## Usage

1.  Load the package (e.g. `(require 'aws-iam-role-viewer)`)
2.  Run:
    `M-x aws-iam-role-viewer-view-details`
3.  Select a role from the list.
4.  View the detailed Org-mode output including:
      * Role metadata
      * Trust policy
      * Permissions boundary
      * All managed and inline policies

### Org Buffer Keybindings

| Keybinding | Description                 |
| :--------- | :-------------------------- |
| `C-c C-h`  | Hide all property drawers   |
| `C-c C-r`  | Reveal all property drawers |

-----

## Configuration

Optional variables for customizing behavior:

```elisp
(setq aws-iam-role-viewer-profile "my-profile") ;; Use a specific AWS CLI profile
(setq aws-iam-role-viewer-show-folded-by-default t) ;; Show Org buffer folded by default
(setq aws-iam-role-viewer-fullscreen nil) ;; Prevent the buffer from taking the full frame
```

To change the profile at runtime, you can run:
`M-x aws-iam-role-viewer-set-profile`
