;;; org-aws-iam-role.el --- Browse and modify AWS IAM Roles in Org Babel -*- lexical-binding: t; -*-

;; Copyright (C) 2025 William Bosch-Bello

;; Author: William Bosch-Bello <williamsbosch@gmail.com>
;; Maintainer: William Bosch-Bello <williamsbosch@gmail.com>
;; Created: August 16, 2025
;; Version: 1.2.0
;; Package-Version: 1.2.0
;; Package-Requires: (emacs "29.1")
;; Keywords: aws, iam, org, babel, tools
;; URL: https://github.com/will-abb/org-aws-iam-role
;; Homepage: https://github.com/will-abb/org-aws-iam-role
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is part of org-aws-iam-role.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by

;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program. If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Provides an interactive interface for browsing and modifying AWS IAM
;; roles directly within Emacs. The package renders all role data in a
;; detailed Org mode buffer and uses a custom Org Babel language,
;; `aws-iam`, to apply policy changes via the AWS CLI.

;; Features include:
;; - Interactive browsing and selection of IAM roles.
;; - Full display of all policy types: Trust Policy, Permissions Boundary,
;; AWS-Managed, Customer-Managed, and Inline policies.
;; - Direct modification of any policy through Org Babel source blocks.
;; - Asynchronous fetching of initial role and policy data for a fast UI.
;; - Safe by default: buffer opens in read-only mode to prevent accidents.
;; - Clear feedback on command success or failure in Babel results blocks.
;; - Integrated keybindings for a smooth workflow:
;; - C-c C-e: Toggle read-only mode to enable/disable editing.
;; - C-c C-c: Apply changes for the policy under the cursor to AWS.
;; - C-c ( / C-c ): Hide or reveal all property drawers.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'url-util)
(require 'async)
(require 'promise)
(require 'ob-shell)
(require 'org)

;; Load the separated modules for Babel and Simulation
(require 'ob-aws-iam)
(require 'org-aws-iam-role-simulate)

;; Register the custom `aws-iam` language with Org Babel
(add-to-list 'org-babel-load-languages '(aws-iam . t))
(add-to-list 'org-src-lang-modes '(("aws-iam" . json)
                                   ("json" . json)))

(defvar org-aws-iam-role-profile nil
  "Default AWS CLI profile to use for IAM role operations.
If nil, uses default profile or environment credentials.")

(defvar org-aws-iam-role-show-folded-by-default nil
  "If non-nil, show the role detail buffer with all sections folded.")

(defvar org-aws-iam-role-fullscreen t
  "If non-nil, show the IAM role buffer in fullscreen.")

(defvar org-aws-iam-role-read-only-by-default t
  "If non-nil, role viewer buffers will be read-only by default.")

;;;###autoload
(cl-defun org-aws-iam-role-view-details (&optional role-name)
  "Display details for an IAM ROLE-NAME in an Org-mode buffer.
If ROLE-NAME is nil and called interactively, prompt the user.
If ROLE-NAME is provided programmatically, skip prompting."
  (interactive)
  (org-aws-iam-role-check-auth)
  (let* ((name (or role-name
                   (when (called-interactively-p 'any)
                     (completing-read "IAM Role: " (org-aws-iam-role-list-names)))))
         (role (org-aws-iam-role-construct
                (org-aws-iam-role-get-full name))))
    (org-aws-iam-role-show-buffer role)))

;;;###autoload
(defun org-aws-iam-role-set-profile ()
  "Prompt for and set the AWS CLI profile for IAM role operations."
  (interactive)
  (let* ((output (shell-command-to-string "aws configure list-profiles"))
         (profiles (split-string output "\n" t)))
    (setq org-aws-iam-role-profile
          (completing-read "Select AWS profile: " profiles nil t))
    (message "Set IAM Role AWS profile to: %s" org-aws-iam-role-profile)))

(defun org-aws-iam-role-toggle-read-only ()
  "Toggle read-only mode in the current buffer and provide feedback."
  (interactive)
  (if buffer-read-only
      (progn
        (read-only-mode -1)
        (message "Buffer is now editable."))
    (progn
      (read-only-mode 1)
      (message "Buffer is now read-only."))))

;;; Internal Helpers & Structs
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun org-aws-iam-role--cli-profile-arg ()
  "Return the AWS CLI profile argument string, or an empty string."
  (if org-aws-iam-role-profile
      (format " --profile %s" (shell-quote-argument org-aws-iam-role-profile))
    ""))

(defun org-aws-iam-role-check-auth ()
  "Ensure the user is authenticated with AWS, raising an error if not."
  (let* ((cmd (format "aws sts get-caller-identity --output json%s"
                      (org-aws-iam-role--cli-profile-arg)))
         (exit-code (shell-command cmd nil nil)))
    ;; A non-zero exit code from the AWS CLI indicates an error like bad credentials).
    (unless (eq exit-code 0)
      (user-error "AWS CLI not authenticated: please check your credentials or AWS_PROFILE"))))

(defun org-aws-iam-role-format-tags (tags)
  "Format AWS TAGS from a list of alists into a single JSON string.

Argument TAGS is a list of alists of the form
\(\(\"Key\" . \"k1\"\) \(\"Value\" . \"v1\"\)\)."
  (when tags
    ;; We simplify this to a single alist '(( "k1" . "v1" )) for easier JSON encoding.
    (let ((simple-alist (mapcar (lambda (tag)
                                  (cons (alist-get 'Key tag)
                                        (alist-get 'Value tag)))
                                tags)))
      (json-encode simple-alist))))

(cl-defstruct org-aws-iam-role
  name
  arn
  role-id
  path
  create-date
  max-session-duration
  trust-policy
  description
  permissions-boundary-type
  permissions-boundary-arn
  tags
  last-used-region
  last-used-date)

(cl-defstruct org-aws-iam-role-policy
  name
  policy-type
  id
  arn
  path
  description
  is-attachable
  create-date
  update-date
  attachment-count
  default-version-id
  document tags)


;;; IAM Policy Data Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun org-aws-iam-role-policy-get-metadata-async (policy-arn)
  "Fetch policy metadata JSON asynchronously for POLICY-ARN.

Returns a promise that resolves with the raw JSON string from the
`get-policy` command."
  (let* ((cmd (format "aws iam get-policy --policy-arn %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (org-aws-iam-role--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise:async-start start-func)))

(defun org-aws-iam-role-policy-get-version-document-async (policy-arn version-id)
  "Fetch policy document JSON for POLICY-ARN and VERSION-ID.

This is an asynchronous operation using `get-policy-version`.
Returns a promise that resolves with the raw JSON string."
  (let* ((cmd (format "aws iam get-policy-version --policy-arn %s --version-id %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (shell-quote-argument version-id)
                      (org-aws-iam-role--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise:async-start start-func)))

(defun org-aws-iam-role-policy--construct-from-data (metadata policy-type document-json)
  "Construct an `org-aws-iam-role-policy` struct from resolved data.

METADATA is the parsed `Policy` alist from `get-policy`.
POLICY-TYPE is the type symbol (e.g., `aws-managed`).
DOCUMENT-JSON is the raw JSON string from `get-policy-version`."
  (let* ((policy-version (alist-get 'PolicyVersion (json-parse-string document-json :object-type 'alist)))
         (document-string (alist-get 'Document policy-version))
         ;; The policy document itself is a URL-encoded JSON string inside the parent JSON.
         (document (when document-string
                     (if (stringp document-string)
                         (json-parse-string (url-unhex-string document-string) :object-type 'alist)
                       document-string))))
    (make-org-aws-iam-role-policy
     :name (alist-get 'PolicyName metadata)
     :policy-type policy-type
     :id (alist-get 'PolicyId metadata)
     :arn (alist-get 'Arn metadata)
     :path (alist-get 'Path metadata)
     :description (alist-get 'Description metadata)
     :is-attachable (alist-get 'IsAttachable metadata)
     :create-date (alist-get 'CreateDate metadata)
     :update-date (alist-get 'UpdateDate metadata)
     :attachment-count (alist-get 'AttachmentCount metadata)
     :default-version-id (alist-get 'DefaultVersionId metadata)
     :document document
     :tags (alist-get 'Tags metadata))))

(defun org-aws-iam-role-policy-from-arn-async (policy-arn policy-type)
  "Create an `org-aws-iam-role-policy` struct asynchronously from a policy ARN.

Argument POLICY-ARN is the ARN of the IAM policy.
Argument POLICY-TYPE is the type of the IAM policy.
Returns a promise that resolves with the complete
`org-aws-iam-role-policy` struct."
  (let ((p (promise-chain
               ;; Step 1: Fetch the policy metadata.
               (org-aws-iam-role-policy-get-metadata-async policy-arn)

             ;; Step 2: From metadata, fetch the policy document.
             (then (lambda (metadata-json)
                     (let* ((metadata (alist-get 'Policy (json-parse-string metadata-json :object-type 'alist)))
                            (version-id (alist-get 'DefaultVersionId metadata)))
                       (if version-id
                           (promise-then (org-aws-iam-role-policy-get-version-document-async policy-arn version-id)
                                         (lambda (document-json)
                                           ;; Pass both results to the next step
                                           (list metadata document-json)))
                         ;; Gracefully fail by resolving to nil if no version-id is found.
                         (promise-resolve nil)))))

             ;; Step 3: Construct the final struct from the resolved data.
             (then (lambda (results)
                     (when results
                       (let ((metadata (car results))
                             (document-json (cadr results)))
                         (org-aws-iam-role-policy--construct-from-data metadata policy-type document-json))))))))
    ;; Step 4: Catch any promise rejection in the chain and resolve to nil.
    (promise-catch p (lambda (&rest _) nil))))

(defun org-aws-iam-role-inline-policy--construct-from-json (policy-name json)
  "Construct an inline `org-aws-iam-role-policy` struct from its JSON.

POLICY-NAME is the name of the inline policy. JSON is the raw
string from the `get-role-policy` AWS CLI command."
  (let* ((parsed (json-parse-string json :object-type 'alist :array-type 'list))
         (document (alist-get 'PolicyDocument parsed))
         ;; The policy document is a URL-encoded JSON string inside the parent JSON.
         (decoded-doc (when document
                        (if (stringp document)
                            (json-parse-string (url-unhex-string document) :object-type 'alist :array-type 'list)
                          document))))
    (make-org-aws-iam-role-policy
     :name policy-name
     :policy-type 'inline
     :document decoded-doc)))

(defun org-aws-iam-role-inline-policy-from-name-async (role-name policy-name)
  "Fetch an inline policy asynchronously and construct a struct.

Argument ROLE-NAME is the name of the IAM role.
Argument POLICY-NAME is the name of the inline policy.
Returns a promise that resolves with the `org-aws-iam-role-policy` struct."
  (let* ((cmd (format "aws iam get-role-policy --role-name %s --policy-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (shell-quote-argument policy-name)
                      (org-aws-iam-role--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise-chain (promise:async-start start-func)
      (then (lambda (json)
              (org-aws-iam-role-inline-policy--construct-from-json policy-name json))))))


;;; IAM Role Data Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun org-aws-iam-role--fetch-roles-page (marker)
  "Fetch a single page of IAM roles from AWS.

If MARKER is non-nil, it's used as the `--starting-token`.
Returns a cons cell: (LIST-OF-ROLES . NEXT-MARKER)."
  (let* ((cmd (format "aws iam list-roles --output json%s%s"
                      (org-aws-iam-role--cli-profile-arg)
                      (if marker
                          (format " --starting-token %s" (shell-quote-argument marker))
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (cons (alist-get 'Roles parsed) (alist-get 'Marker parsed))))

(defun org-aws-iam-role-list-names ()
  "Return a list of all IAM role names, handling pagination."
  (let ((all-roles '())
        (marker nil)
        (first-run t))
    ;; Loop until the AWS API returns no more pages (i.e., the marker is nil).
    ;; The `first-run` flag ensures the loop runs at least once when marker starts as nil.
    (while (or first-run marker)
      (let* ((page-result (org-aws-iam-role--fetch-roles-page marker))
             (roles-on-page (car page-result))
             (next-marker (cdr page-result)))
        (setq all-roles (nconc all-roles roles-on-page))
        (setq marker next-marker)
        (setq first-run nil)))
    (mapcar (lambda (r) (alist-get 'RoleName r)) all-roles)))

(defun org-aws-iam-role-get-full (role-name)
  "Fetch full IAM role object for ROLE-NAME from AWS using `get-role`."
  (let* ((cmd (format "aws iam get-role --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (org-aws-iam-role--cli-profile-arg)))
         (json (shell-command-to-string cmd))
         (parsed (alist-get 'Role (json-parse-string json :object-type 'alist :array-type 'list))))
    parsed))

(defun org-aws-iam-role-construct (obj)
  "Create an `org-aws-iam-role` struct from a full `get-role` object.

Argument OBJ is the JSON object returned by `get-role`."
  ;; PermissionsBoundary and RoleLastUsed can be nil, so we get them first.
  (let ((pb (alist-get 'PermissionsBoundary obj))
        (last-used (alist-get 'RoleLastUsed obj)))
    (make-org-aws-iam-role
     :name (alist-get 'RoleName obj)
     :arn (alist-get 'Arn obj)
     :role-id (alist-get 'RoleId obj)
     :path (alist-get 'Path obj)
     :create-date (alist-get 'CreateDate obj)
     :max-session-duration (alist-get 'MaxSessionDuration obj)
     :trust-policy (alist-get 'AssumeRolePolicyDocument obj)
     :description (alist-get 'Description obj)
     :permissions-boundary-type (alist-get 'PermissionsBoundaryType pb)
     :permissions-boundary-arn (alist-get 'PermissionsBoundaryArn pb)
     :tags (alist-get 'Tags obj)
     :last-used-region (alist-get 'Region last-used)
     :last-used-date (alist-get 'LastUsedDate last-used))))

(defun org-aws-iam-role-attached-policies (role-name)
  "Return list of attached managed policies for ROLE-NAME."
  (let* ((cmd (format "aws iam list-attached-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (org-aws-iam-role--cli-profile-arg)))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'AttachedPolicies parsed)))

(defun org-aws-iam-role-inline-policies (role-name)
  "Return list of inline policy names for ROLE-NAME."
  (let* ((cmd (format "aws iam list-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (org-aws-iam-role--cli-profile-arg)))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'PolicyNames parsed)))

(defun org-aws-iam-role-split-managed-policies (attached)
  "Split ATTACHED managed policies into (customer . aws) buckets.

Each bucket keeps the full alist for each policy item."
  (let ((customer '()) (aws '()))
    (dolist (p attached)
      (let ((arn (alist-get 'PolicyArn p)))
        ;; AWS-managed policies have a standard, well-known ARN prefix.
        (if (string-prefix-p "arn:aws:iam::aws:policy/" arn)
            (push p aws)
          (push p customer))))
    (cons (nreverse customer) (nreverse aws))))

;;; Display Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun org-aws-iam-role-insert-role-header (role)
  "Insert the main heading and properties for ROLE into the buffer."
  (insert (format "* IAM Role: %s\n" (org-aws-iam-role-name role)))
  (insert ":PROPERTIES:\n")
  (insert (format ":ARN: %s\n" (org-aws-iam-role-arn role)))
  (insert (format ":RoleID: %s\n" (org-aws-iam-role-role-id role)))
  (insert (format ":Path: %s\n" (org-aws-iam-role-path role)))
  (insert (format ":Created: %s\n" (org-aws-iam-role-create-date role)))
  (insert (format ":MaxSessionDuration: %d\n" (org-aws-iam-role-max-session-duration role)))
  ;; Use "nil" as a string for display if the actual value is nil.
  (insert (format ":Description: %s\n" (or (org-aws-iam-role-description role) "nil")))
  (insert (format ":PermissionsBoundaryArn: %s\n" (or (org-aws-iam-role-permissions-boundary-arn role) "nil")))
  (insert (format ":LastUsedDate: %s\n" (or (org-aws-iam-role-last-used-date role) "nil")))
  (insert (format ":LastUsedRegion: %s\n" (or (org-aws-iam-role-last-used-region role) "nil")))
  (insert (format ":Tags: %s\n" (or (org-aws-iam-role-format-tags (org-aws-iam-role-tags role)) "nil")))
  (insert ":END:\n"))

(defun org-aws-iam-role-insert-trust-policy (role)
  "Insert the trust policy section for ROLE into the buffer."
  (let ((trust-policy-json (json-encode (org-aws-iam-role-trust-policy role)))
        (role-name (org-aws-iam-role-name role)))
    (insert "** Trust Policy\n")
    (insert (format "#+BEGIN_SRC aws-iam :role-name \"%s\" :policy-type \"trust-policy\" :results output\n" role-name))
    (let ((start (point)))
      (insert trust-policy-json)
      ;; Don't let a JSON formatting error stop buffer creation.
      (condition-case nil
          (json-pretty-print start (point))
        (error nil)))
    (insert "\n#+END_SRC\n")))

(defun org-aws-iam-role--format-policy-type (policy-type-symbol)
  "Format POLICY-TYPE-SYMBOL into a human-readable string."
  (cond ((eq policy-type-symbol 'aws-managed) "AWS Managed")
        ((eq policy-type-symbol 'customer-managed) "Customer Managed")
        ((eq policy-type-symbol 'inline) "Inline")
        ((eq policy-type-symbol 'permissions-boundary) "Permissions Boundary")
        (t (capitalize (symbol-name policy-type-symbol)))))

(defun org-aws-iam-role--insert-policy-struct-details (policy role-name)
  "Insert details of a POLICY struct into the buffer for ROLE-NAME."
  (let* ((doc-json (json-encode (org-aws-iam-role-policy-document policy)))
         (policy-type-symbol (org-aws-iam-role-policy-policy-type policy))
         (policy-arn (or (org-aws-iam-role-policy-arn policy) "")))
    (insert (format "*** %s\n" (org-aws-iam-role-policy-name policy)))
    (insert ":PROPERTIES:\n")
    (insert (format ":AWSPolicyType: %s\n" (org-aws-iam-role--format-policy-type policy-type-symbol)))
    (insert (format ":ID: %s\n" (or (org-aws-iam-role-policy-id policy) "nil")))
    (insert (format ":ARN: %s\n" (or policy-arn "nil")))
    (insert (format ":Path: %s\n" (or (org-aws-iam-role-policy-path policy) "nil")))
    (insert (format ":Description: %s\n" (or (org-aws-iam-role-policy-description policy) "nil")))
    (insert (format ":Created: %s\n" (or (org-aws-iam-role-policy-create-date policy) "nil")))
    (insert (format ":Updated: %s\n" (or (org-aws-iam-role-policy-update-date policy) "nil")))
    (insert (format ":AttachmentCount: %s\n" (or (org-aws-iam-role-policy-attachment-count policy) "nil")))
    (insert (format ":DefaultVersion: %s\n" (or (org-aws-iam-role-policy-default-version-id policy) "nil")))
    (insert ":END:\n")
    (insert (format "#+BEGIN_SRC aws-iam :role-name \"%s\" :policy-name \"%s\" :policy-type \"%s\" :arn \"%s\" :results output\n"
                    role-name
                    (org-aws-iam-role-policy-name policy)
                    (symbol-name policy-type-symbol)
                    policy-arn))
    (let ((start (point)))
      (insert doc-json)
      (condition-case nil
          (json-pretty-print start (point))
        (error nil)))
    (insert "\n#+END_SRC\n")))

(defun org-aws-iam-role--insert-remaining-sections-and-finalize (role buf)
  "Insert remaining sections for ROLE and finalize display of BUF."
  (with-current-buffer buf
    (org-aws-iam-role-insert-trust-policy role))
  (org-aws-iam-role-finalize-and-display-role-buffer buf))

(defun org-aws-iam-role--create-policy-promises (role-name boundary-arn attached-policies inline-policy-names)
  "Create a list of promises to fetch all policies.
ROLE-NAME is the role name. BOUNDARY-ARN is its boundary ARN.
ATTACHED-POLICIES is a list of attached policies.
INLINE-POLICY-NAMES is a list of inline policy names."
  (let* ((split (org-aws-iam-role-split-managed-policies attached-policies))
         (customer-managed (car split))
         (aws-managed (cdr split))
         (aws-promises (mapcar (lambda (p) (org-aws-iam-role-policy-from-arn-async (alist-get 'PolicyArn p) 'aws-managed)) aws-managed))
         (customer-promises (mapcar (lambda (p) (org-aws-iam-role-policy-from-arn-async (alist-get 'PolicyArn p) 'customer-managed)) customer-managed))
         (boundary-promise (when boundary-arn (list (org-aws-iam-role-policy-from-arn-async boundary-arn 'permissions-boundary))))
         (inline-promises (mapcar (lambda (name) (org-aws-iam-role-inline-policy-from-name-async role-name name)) inline-policy-names)))
    (append aws-promises customer-promises boundary-promise inline-promises)))

(defun org-aws-iam-role--get-all-policies-async (role)
  "Fetch all attached, inline, and boundary policies for ROLE.

This function is asynchronous and returns a single promise that
resolves with a vector of `org-aws-iam-role-policy` structs when
all underlying fetches are complete. Returns nil if no policies
are found."
  (let* ((role-name (org-aws-iam-role-name role))
         (attached (org-aws-iam-role-attached-policies role-name))
         (inline-policy-names (org-aws-iam-role-inline-policies role-name))
         (boundary-arn (org-aws-iam-role-permissions-boundary-arn role))
         (all-promises (org-aws-iam-role--create-policy-promises
                        role-name boundary-arn attached inline-policy-names)))
    (when all-promises
      (promise-all all-promises))))

(defun org-aws-iam-role--insert-policies-section (all-policies-vector boundary-arn role-name)
  "Render a vector of fetched policies into the current buffer.

ALL-POLICIES-VECTOR is the result from a `promise-all' call.
BOUNDARY-ARN is the original ARN of the boundary policy.
ROLE-NAME is the name of the parent IAM role."
  (let* ((policies-list (seq-into all-policies-vector 'list))
         ;; Filter out any nil results from promises that may have failed gracefully.
         (valid-policies (cl-remove-if-not #'identity policies-list))
         ;; Separate boundary policy from the rest for individual rendering.
         (boundary-policy (cl-find 'permissions-boundary valid-policies :key #'org-aws-iam-role-policy-policy-type))
         (permission-policies (cl-remove 'permissions-boundary valid-policies :key #'org-aws-iam-role-policy-policy-type)))

    ;; 1. Render Permission Policies (AWS, Customer, Inline)
    (insert "** Permission Policies\n")
    (if permission-policies
        (dolist (p permission-policies) (org-aws-iam-role--insert-policy-struct-details p role-name))
      (insert "nil\n"))

    ;; 2. Render Permissions Boundary Policy
    (when boundary-arn
      (insert "** Permissions Boundary Policy\n")
      (if boundary-policy
          (org-aws-iam-role--insert-policy-struct-details boundary-policy role-name)
        (insert "Failed to fetch permissions boundary policy.\n")))))

(defun org-aws-iam-role--insert-buffer-usage-notes ()
  "Insert the usage and keybinding notes into the current buffer."
  (insert "* Usage\n")
  (insert "** Applying Changes via Babel\n")
  (insert "All actions are performed by executing an =aws-iam= source block with =C-c C-c=.\n")
  (insert "You will be asked to confirm before any change is applied.\n")
  (insert "\n- *To Create or Update an Inline Policy*, simply write or edit its source block and execute it. No special flag is needed.\n")
  (insert "- *To Update any other policy*, edit its source block and execute.\n")
  (insert "\nUse header arguments for other actions:\n")
  (insert "- =:create t=     :: Creates a new *customer-managed* policy.\n")
  (insert "- =:delete t=     :: Deletes a policy. For managed policies, this will fail if the policy is still attached to any role, user, or group.\n")
  (insert "- =:detach t=     :: Detaches a *managed* policy from the current role.\n")
  (insert "\n** Keybindings\n")
  (insert "- =C-c C-e= :: Toggle read-only mode to allow/prevent edits.\n")
  (insert "- =C-c C-s= :: Simulate the role's policies against specific actions.\n")
  (insert "- =C-c C-c= :: Inside a source block, apply changes to AWS.\n")
  (insert "- =C-c (= :: Hide all property drawers.\n")
  (insert "- =C-c )= :: Reveal all property drawers.\n\n"))

(defun org-aws-iam-role--populate-buffer-async-callback (all-policies-vector role buf)
  "Callback to populate BUF with fetched policies for ROLE.
ALL-POLICIES-VECTOR is the resolved vector of policy structs."
  ;; Catch any error during rendering to prevent the callback from crashing.
  (condition-case nil
      (with-current-buffer buf
        (let ((boundary-arn (org-aws-iam-role-permissions-boundary-arn role))
              (role-name (org-aws-iam-role-name role)))
          ;; Insert the fetched policy sections.
          (org-aws-iam-role--insert-policies-section all-policies-vector boundary-arn role-name)
          ;; Insert remaining synchronous sections and finalize the buffer.
          (org-aws-iam-role--insert-remaining-sections-and-finalize role buf)))
    (error nil)))

(defun org-aws-iam-role-populate-role-buffer (role buf)
  "Insert all details for ROLE and its policies into the buffer BUF.
This function orchestrates the asynchronous fetching and rendering of role
information."
  (with-current-buffer buf
    (erase-buffer)
    (org-mode)
    (setq-local org-src-fontify-natively t)
    (org-aws-iam-role--insert-buffer-usage-notes)
    (org-aws-iam-role-insert-role-header role))

  ;; Asynchronously fetch all policies for the role.
  (let ((policies-promise (org-aws-iam-role--get-all-policies-async role)))
    ;; If there are policies, wait for them and then render. Otherwise, render the empty state.
    (if policies-promise
        (promise-then
         policies-promise
         (lambda (all-policies-vector)
           (org-aws-iam-role--populate-buffer-async-callback all-policies-vector role buf)))
      ;; Case where there are no policies of any kind.
      (with-current-buffer buf
        (insert "** Permission Policies\n")
        (insert "nil\n")
        (org-aws-iam-role--insert-remaining-sections-and-finalize role buf)))))

(defun org-aws-iam-role-finalize-and-display-role-buffer (buf)
  "Set keybinds, mode, and display the buffer BUF."
  (with-current-buffer buf
    (local-set-key (kbd "C-c C-e") #'org-aws-iam-role-toggle-read-only)
    (local-set-key (kbd "C-c C-s") #'org-aws-iam-role-simulate-from-buffer)
    (local-set-key (kbd "C-c (") #'org-fold-hide-drawer-all)
    (local-set-key (kbd "C-c )") #'org-fold-show-all)
    (goto-char (point-min))    (when org-aws-iam-role-read-only-by-default
                                 (read-only-mode 1))
    (if org-aws-iam-role-show-folded-by-default
        (org-overview)
      (org-fold-show-all)))
  ;; Display in a pop-up window.
  (let ((window (display-buffer buf '((display-buffer-pop-up-window)))))
    ;; If fullscreen is enabled, make this the only window.
    (when (and org-aws-iam-role-fullscreen (window-live-p window))
      (select-window window)
      (delete-other-windows))))

(defun org-aws-iam-role-show-buffer (role)
  "Render IAM ROLE object and its policies in a new Org-mode buffer."
  (let* ((timestamp (format-time-string "%Y%m%d-%H%M%S"))
         ;; Add a timestamp to the buffer name for uniqueness.
         (buf-name (format "*IAM Role: %s <%s>*"
                           (org-aws-iam-role-name role)
                           timestamp))
         (buf (get-buffer-create buf-name)))
    (org-aws-iam-role-populate-role-buffer role buf)))

(provide 'org-aws-iam-role)
;;; org-aws-iam-role.el ends here
