# IAM Role Viewer for Emacs

`iam-role.el` is an Emacs package for inspecting AWS IAM roles, viewing policy documents, and running basic permission simulations. It renders all role data—including trust policies, permissions boundaries, and all associated policies (AWS managed, customer managed, and inline)—in an Org-mode buffer using AWS CLI under the hood.

⚠️ **Warning**: None of the AWS CLI calls are executed in parallel, so you will have to wait around a second per policy. For a with 40 policies, loading may take more than 30 seconds.

---

## Features

* **Inspect IAM Roles** via interactive prompt and Org-mode buffer
* **Displays**:

  * Trust policy
  * Permissions boundary
  * Customer-managed policies
  * AWS-managed policies
  * Inline policies
* **Run IAM Simulations** using `simulate-principal-policy`
* **Org-mode Rendering** with foldable sections
* **Switch AWS CLI profiles** interactively
* **Authenticates via CLI** and alerts on credential issues

---

## Requirements

* GNU Emacs 27+
* AWS CLI installed and in your `PATH`
* Permissions for the following AWS IAM APIs:

  * `get-role`
  * `list-attached-role-policies`
  * `list-role-policies`
  * `get-policy`
  * `get-policy-version`
  * `get-role-policy`
  * `simulate-principal-policy`
  * `sts get-caller-identity`

Standard Emacs libraries used: `cl-lib`, `json`, `url-util`, `async` (included in modern Emacs distributions).

---

## Usage

1. Load the package (e.g. `(require 'iam-role)`)
2. Run:
   `M-x aws-iam-role-view-details`
3. Select a role from the list
4. View detailed Org-mode output including:

   * Role metadata
   * Trust policy
   * Permissions boundary
   * All managed and inline policies
   * Optional simulation interface

### Org Buffer Keybindings

| Keybinding | Description                      |
| ---------- | -------------------------------- |
| `C-c C-s`  | Simulate action(s) for this role |
| `C-c C-h`  | Hide all property drawers        |
| `C-c C-r`  | Reveal all property drawers      |

---

## Configuration

Optional variables for customizing behavior:

```elisp
(setq aws-iam-role-profile "my-profile") ;; Use specific AWS CLI profile
(setq aws-iam-role-show-folded-by-default t) ;; Show Org buffer folded by default
(setq aws-iam-role-fullscreen nil) ;; Prevent fullscreen buffer
```

To change profile at runtime:

```elisp
M-x aws-iam-role-set-profile
```

---

## IAM Simulation Notes

The simulation (`simulate-principal-policy`) is intentionally simplified:

* Only evaluates identity-based policies
* Does **not** include resource-based policies (e.g., S3 bucket policies)
* Does **not** evaluate policies with complex context (e.g., source IPs, MFA)
* Does **not** simulate behavior affected by permission conditions
* Results **are** impacted by Service Control Policies (SCPs), but not displayed

For full simulation behavior, use the [AWS IAM Policy Simulator Console](https://policysim.aws.amazon.com/).
