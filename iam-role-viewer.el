;;; iam-role.el --- IAM Role and Policy object browser -*- lexical-binding: t; -*-

(require 'cl-lib)
(require 'json)
(require 'url-util)

(defvar aws-iam-role-viewer-profile nil
  "Default AWS CLI profile to use for IAM role operations.
If nil, uses default profile or environment credentials.")

(defvar aws-iam-role-viewer-show-folded-by-default nil
  "If non-nil, show the role detail buffer with all sections folded.")

(defvar aws-iam-role-viewer-fullscreen t
  "If non-nil, show the IAM role buffer in fullscreen.")

;;;###autoload
(defun aws-iam-role-viewer-view-details ()
  "Prompt for an IAM role and display its details in an Org-mode buffer."
  (interactive)
  (aws-iam-role-viewer-check-auth)
  (let* ((name (completing-read "IAM Role: " (aws-iam-role-viewer-list-names)))
         (role (aws-iam-role-viewer-construct
                (aws-iam-role-viewer-get-full name))))
    (aws-iam-role-viewer-show-buffer role)))

;;;###autoload
(defun aws-iam-role-viewer-set-profile ()
  "Prompt for and set the AWS CLI profile for IAM role operations."
  (interactive)
  (let* ((output (shell-command-to-string "aws configure list-profiles"))
         (profiles (split-string output "\n" t)))
    (setq aws-iam-role-viewer-profile
          (completing-read "Select AWS profile: " profiles nil t))
    (message "Set IAM Role AWS profile to: %s" aws-iam-role-viewer-profile)))

;;; Internal Helpers & Structs
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer-check-auth ()
  "Ensure the user is authenticated with AWS. Raise error if not."
  (let* ((cmd (format "aws sts get-caller-identity --output json%s"
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (exit-code (shell-command cmd nil nil)))
    (unless (eq exit-code 0)
      (user-error "AWS CLI not authenticated: please check your credentials or AWS_PROFILE"))))

(defun aws-iam-format-tags (tags)
  "Format AWS tags from a list of alists into a single JSON string."
  (when tags
    (let ((simple-alist (mapcar (lambda (tag)
                                  (cons (alist-get 'Key tag)
                                        (alist-get 'Value tag)))
                                tags)))
      (json-encode simple-alist))))

(cl-defstruct aws-iam-role-viewer
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

(cl-defstruct aws-iam-policy
  name
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

(defun aws-iam-policy-get-metadata (policy-arn)
  "Fetch policy metadata from AWS using `get-policy`."
  (let* ((cmd (format "aws iam get-policy --policy-arn %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd)))
    (alist-get 'Policy (json-parse-string json :object-type 'alist :array-type 'list))))

(defun aws-iam-policy-get-version-document (policy-arn version-id)
  "Fetch and decode a policy document from AWS using `get-policy-version`."
  (let* ((cmd (format "aws iam get-policy-version --policy-arn %s --version-id %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (shell-quote-argument version-id)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (policy-version (alist-get 'PolicyVersion (json-parse-string json :object-type 'alist :array-type 'list)))
         (document (alist-get 'Document policy-version)))
    (when document
      (if (stringp document)
          (json-parse-string (url-unhex-string document) :object-type 'alist :array-type 'list)
        document))))

(defun aws-iam-policy-from-arn (policy-arn)
  "Create an `aws-iam-policy' struct from a policy ARN by calling AWS."
  (let* ((metadata (aws-iam-policy-get-metadata policy-arn))
         (version-id (alist-get 'DefaultVersionId metadata))
         (document (aws-iam-policy-get-version-document policy-arn version-id)))
    (make-aws-iam-policy
     :name (alist-get 'PolicyName metadata)
     :id (alist-get 'PolicyId metadata)
     :arn (alist-get 'Arn metadata)
     :path (alist-get 'Path metadata)
     :description (alist-get 'Description metadata)
     :is-attachable (alist-get 'IsAttachable metadata)
     :create-date (alist-get 'CreateDate metadata)
     :update-date (alist-get 'UpdateDate metadata)
     :attachment-count (alist-get 'AttachmentCount metadata)
     :default-version-id version-id
     :document document
     :tags (alist-get 'Tags metadata))))


;;; IAM Role Data Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer-list-names ()
  "Return a list of IAM role names using `list-roles`."
  (let ((all-roles '())
        (marker nil)
        (first-run t))
    (while (or first-run marker)
      (let* ((cmd (format "aws iam list-roles --output json%s%s"
                          (if aws-iam-role-viewer-profile
                              (format " --profile %s" aws-iam-role-viewer-profile)
                            "")
                          (if marker
                              (format " --starting-token %s" (shell-quote-argument marker))
                            "")))
             (json (shell-command-to-string cmd))
             (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
        (setq all-roles (nconc all-roles (alist-get 'Roles parsed)))
        (setq marker (alist-get 'Marker parsed))
        (setq first-run nil)))
    (mapcar (lambda (r) (alist-get 'RoleName r)) all-roles)))

(defun aws-iam-role-viewer-get-full (role-name)
  "Fetch full IAM role object from AWS using `get-role`."
  (let* ((cmd (format "aws iam get-role --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (alist-get 'Role (json-parse-string json :object-type 'alist :array-type 'list))))
    parsed))

(defun aws-iam-role-viewer-construct (obj)
  "Create an `aws-iam-role-viewer` struct from a full `get-role` object."
  (let ((pb (alist-get 'PermissionsBoundary obj))
        (last-used (alist-get 'RoleLastUsed obj)))
    (make-aws-iam-role-viewer
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

(defun aws-iam-role-viewer-attached-policies (role-name)
  "Return list of attached managed policies for ROLE-NAME."
  (let* ((cmd (format "aws iam list-attached-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'AttachedPolicies parsed)))

(defun aws-iam-role-viewer-inline-policies (role-name)
  "Return list of inline policy names for ROLE-NAME."
  (let* ((cmd (format "aws iam list-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'PolicyNames parsed)))

(defun aws-iam-role-viewer-get-inline-policy-document (role-name policy-name)
  "Fetch and decode an inline policy document for a role."
  (let* ((cmd (format "aws iam get-role-policy --role-name %s --policy-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (shell-quote-argument policy-name)
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list))
         (document (alist-get 'PolicyDocument parsed)))
    (when document
      (if (stringp document)
          (json-parse-string (url-unhex-string document) :object-type 'alist :array-type 'list)
        document))))

(defun aws-iam-role-viewer-split-managed-policies (attached)
  "Split ATTACHED managed policies into (customer . aws) buckets, keeping full alist per item."
  (let ((customer '()) (aws '()))
    (dolist (p attached)
      (let ((arn (alist-get 'PolicyArn p)))
        (if (string-prefix-p "arn:aws:iam::aws:policy/" arn)
            (push p aws)
          (push p customer))))
    (cons (nreverse customer) (nreverse aws))))


;;; Simulation Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer-simulate-policy-for-arn (role-arn)
  "Given a ROLE-ARN, prompt for an action and simulate the policy."
  (let* ((actions-str (read-string "Action(s) to test (e.g., s3:ListObjects s3:Upload*): "))
         (resources-str (read-string "Resource ARN(s) (e.g., arn:aws:s3:::biowebsite): "))
         ;; Split the input strings into lists, then format each item for the shell.
         (action-args (mapconcat #'shell-quote-argument (split-string actions-str nil t " +") " "))
         (resource-args (if (string-empty-p resources-str)
                            ""
                          (concat " --resource-arns "
                                  (mapconcat #'shell-quote-argument (split-string resources-str nil t " +") " "))))
         (cmd (format "aws iam simulate-principal-policy --policy-source-arn %s --action-names %s%s --output json%s"
                      (shell-quote-argument role-arn)
                      action-args
                      resource-args
                      (if aws-iam-role-viewer-profile
                          (format " --profile %s" aws-iam-role-viewer-profile)
                        "")))
         (json (shell-command-to-string cmd))
         (results (alist-get 'EvaluationResults (json-parse-string json :object-type 'alist :array-type 'list))))
    (aws-iam-role-viewer-show-simulation-result results)))

(defun aws-iam-role-viewer-simulate-from-buffer ()
  "Run a policy simulation using the ARN from the current role buffer."
  (interactive)
  (save-excursion
    (goto-char (point-min))
    (if (re-search-forward "^:ARN:[ \t]+\\(arn:aws:iam::.*\\)$" nil t)
        (let ((role-arn (match-string 1)))
          (aws-iam-role-viewer-simulate-policy-for-arn role-arn))
      (user-error "Could not find a valid Role ARN in this buffer."))))


;;; Display Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer-insert-role-header (role)
  "Insert the main role heading and properties into the buffer."
  (insert (format "* IAM Role: %s\n" (aws-iam-role-viewer-name role)))
  (insert ":PROPERTIES:\n")
  (insert (format ":ARN: %s\n" (aws-iam-role-viewer-arn role)))
  (insert (format ":RoleID: %s\n" (aws-iam-role-viewer-role-id role)))
  (insert (format ":Path: %s\n" (aws-iam-role-viewer-path role)))
  (insert (format ":Created: %s\n" (aws-iam-role-viewer-create-date role)))
  (insert (format ":MaxSessionDuration: %d\n" (aws-iam-role-viewer-max-session-duration role)))
  (insert (format ":Description: %s\n" (or (aws-iam-role-viewer-description role) "nil")))
  (insert (format ":PermissionsBoundaryArn: %s\n" (or (aws-iam-role-viewer-permissions-boundary-arn role) "nil")))
  (insert (format ":LastUsedDate: %s\n" (or (aws-iam-role-viewer-last-used-date role) "nil")))
  (insert (format ":LastUsedRegion: %s\n" (or (aws-iam-role-viewer-last-used-region role) "nil")))
  (insert (format ":Tags: %s\n" (or (aws-iam-format-tags (aws-iam-role-viewer-tags role)) "nil")))
  (insert ":END:\n"))

(defun aws-iam-role-viewer-insert-trust-policy (role)
  "Insert the trust policy section into the buffer."
  (let ((trust-policy-json (json-encode (aws-iam-role-viewer-trust-policy role))))
    (insert "** Trust Policy\n")
    (insert "#+BEGIN_SRC json\n")
    (let ((start (point)))
      (insert trust-policy-json)
      (json-pretty-print start (point)))
    (insert "\n#+END_SRC\n")))

(defun aws-iam-role-viewer-insert-managed-policy-details (policy-arn)
  "Fetch a managed policy by ARN and insert its details into the buffer."
  (let* ((policy (aws-iam-policy-from-arn policy-arn))
         (doc-json (json-encode (aws-iam-policy-document policy))))
    (insert (format "*** %s\n" (aws-iam-policy-name policy)))
    (insert ":PROPERTIES:\n")
    (insert (format ":ID: %s\n" (or (aws-iam-policy-id policy) "nil")))
    (insert (format ":ARN: %s\n" (or (aws-iam-policy-arn policy) "nil")))
    (insert (format ":Path: %s\n" (or (aws-iam-policy-path policy) "nil")))
    (insert (format ":Description: %s\n" (or (aws-iam-policy-description policy) "nil")))
    (insert (format ":Created: %s\n" (or (aws-iam-policy-create-date policy) "nil")))
    (insert (format ":Updated: %s\n" (or (aws-iam-policy-update-date policy) "nil")))
    (insert (format ":AttachmentCount: %s\n" (or (aws-iam-policy-attachment-count policy) "nil")))
    (insert (format ":DefaultVersion: %s\n" (or (aws-iam-policy-default-version-id policy) "nil")))
    (insert ":END:\n")
    (insert "Policy Document:\n")
    (insert "#+BEGIN_SRC json\n")
    (let ((start (point)))
      (insert doc-json)
      (json-pretty-print start (point)))
    (insert "\n#+END_SRC\n")))

(defun aws-iam-role-viewer-insert-managed-policy-section (title policies)
  "Insert a section TITLE and the details for a list of POLICIES."
  (insert title)
  (if policies
      (dolist (p policies)
        (aws-iam-role-viewer-insert-managed-policy-details (alist-get 'PolicyArn p)))
    (insert "nil\n")))

(defun aws-iam-role-viewer-insert-inline-policies (role)
  "Insert the inline policies section into the buffer."
  (let ((inline-names (aws-iam-role-viewer-inline-policies (aws-iam-role-viewer-name role))))
    (insert "** Inline Policies\n")
    (if inline-names
        (dolist (name inline-names)
          (let* ((doc (aws-iam-role-viewer-get-inline-policy-document (aws-iam-role-viewer-name role) name))
                 (doc-json (json-encode doc)))
            (insert (format "*** %s\n" name))
            (insert "#+BEGIN_SRC json\n")
            (let ((start (point)))
              (insert doc-json)
              (json-pretty-print start (point)))
            (insert "\n#+END_SRC\n")))
      (insert "nil\n"))))

(defun aws-iam-role-viewer-insert-simulation-warning ()
  "Insert the standard simulation warning into the current buffer."
  (let ((start (point)))
    (insert "*** WARNING: Simplified Simulation ***\n")
    (insert "This test only checks the role's identity-based policies against the given actions.\n")
    (insert "- It does NOT include resource-based policies (e.g., S3 bucket policies).\n")
    (insert "- It does NOT allow providing specific context keys (e.g., source IP, MFA).\n")
    (insert "- Results ARE affected by Service Control Policies (SCPs), which can add restrictions.\n\n")
    (insert "For comprehensive testing, use the AWS Console Policy Simulator.\n")
    (insert "************************************\n\n")
    (add-face-text-property start (point) 'font-lock-warning-face)))

(defun aws-iam-role-viewer-parse-simulation-result-item (result-item)
  "Parse a RESULT-ITEM from simulation into a plist for display."
  (let* ((decision (alist-get 'EvalDecision result-item))
         (pb-detail (alist-get 'PermissionsBoundaryDecisionDetail result-item))
         (matched-statements (alist-get 'MatchedStatements result-item))
         (policy-ids (if matched-statements
                         (mapcar (lambda (stmt) (alist-get 'SourcePolicyId stmt)) matched-statements)
                       '("None")))
         (missing-context (alist-get 'MissingContextValues result-item)))
    `(:action ,(alist-get 'EvalActionName result-item)
      :decision ,decision
      :resource ,(alist-get 'EvalResourceName result-item)
      :pb-allowed ,(if pb-detail (alist-get 'AllowedByPermissionsBoundary pb-detail) "N/A")
      :policy-ids-str ,(mapconcat #'identity policy-ids ", ")
      :missing-context-str ,(if missing-context (mapconcat 'identity missing-context ", ") "None")
      :decision-face ,(if (string= decision "allowed") 'success 'error))))

(defun aws-iam-role-viewer-insert-parsed-simulation-result (parsed-result)
  "Insert a PARSED-RESULT plist into the current buffer."
  (insert (propertize "====================================\n" 'face 'shadow))
  (insert (propertize "Action: " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :action) 'face 'font-lock-function-name-face))
  (insert "\n")
  (insert (propertize "------------------------------------\n" 'face 'shadow))
  (insert (propertize "Decision:      " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :decision) 'face (plist-get parsed-result :decision-face)))
  (insert "\n")
  (insert (propertize "Resource:      " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :resource) 'face 'font-lock-string-face))
  (insert "\n")
  (insert (propertize "Boundary Allowed: " 'face 'font-lock-keyword-face))
  (insert (format "%s" (plist-get parsed-result :pb-allowed)))
  (insert "\n")
  (insert (propertize "Matched Policies: " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :policy-ids-str) 'face 'font-lock-doc-face))
  (insert "\n")
  (insert (propertize "Missing Context:  " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :missing-context-str) 'face 'font-lock-comment-face))
  (insert "\n\n"))

(defun aws-iam-role-viewer-insert-one-simulation-result (result-item)
  "Parse and insert the formatted details for a single simulation RESULT-ITEM."
  (let ((parsed-result (aws-iam-role-viewer-parse-simulation-result-item result-item)))
    (aws-iam-role-viewer-insert-parsed-simulation-result parsed-result)))

(defun aws-iam-role-viewer-show-simulation-result (results-list)
  "Display the detailed results of a policy simulation in a new buffer."
  (let ((buf (get-buffer-create "*IAM Simulation Result*")))
    (with-current-buffer buf
      (erase-buffer)
      (aws-iam-role-viewer-insert-simulation-warning)
      (unless results-list
        (insert (propertize "No simulation results returned. Check the AWS CLI command for errors."
                            'face 'error))
        (pop-to-buffer buf)
        (return-from aws-iam-role-viewer-show-simulation-result))
      (dolist (result-item results-list)
        (aws-iam-role-viewer-insert-one-simulation-result result-item))
      (goto-char (point-min))
      (pop-to-buffer buf))))

(defun aws-iam-role-viewer-populate-role-buffer (role buf)
  "Insert all role details and policies into the buffer BUF."
  (with-current-buffer buf
    (erase-buffer)
    (org-mode)
    (aws-iam-role-viewer-insert-role-header role)
    (insert "\n;; --- Keybinds --- \n")
    (insert ";; C-c C-s : Simulate policy for this role\n")
    (insert ";; C-c C-h : Hide all property drawers\n")
    (insert ";; C-c C-r : Reveal all property drawers\n\n")

    (let* ((attached (aws-iam-role-viewer-attached-policies (aws-iam-role-viewer-name role)))
           (split (aws-iam-role-viewer-split-managed-policies attached)))
      (aws-iam-role-viewer-insert-managed-policy-section "** AWS Managed Policies\n" (cdr split))
      (aws-iam-role-viewer-insert-managed-policy-section "** Customer Managed Policies\n" (car split)))

    (aws-iam-role-viewer-insert-inline-policies role)

    (when (aws-iam-role-viewer-permissions-boundary-arn role)
      (insert "** Permissions Boundary Policy\n")
      (aws-iam-role-viewer-insert-managed-policy-details (aws-iam-role-viewer-permissions-boundary-arn role)))

    (aws-iam-role-viewer-insert-trust-policy role)))

(defun aws-iam-role-viewer-show-all-drawers ()
  "Show all drawers in Org buffer using org-fold."
  (interactive)
  (org-fold-show-all))

(defun aws-iam-role-viewer-finalize-and-display-role-buffer (buf)
  "Set keybinds, mode, and display the buffer BUF."
  (with-current-buffer buf
    (local-set-key (kbd "C-c C-s") #'aws-iam-role-viewer-simulate-from-buffer)
    (local-set-key (kbd "C-c C-h") #'org-fold-hide-drawer-all)
    (local-set-key (kbd "C-c C-r") #'aws-iam-role-viewer-show-all-drawers)

    (goto-char (point-min))
    (read-only-mode 1)
    (if aws-iam-role-viewer-show-folded-by-default
        (org-overview)
      (org-fold-show-all)))

  (let ((window (display-buffer buf '((display-buffer-pop-up-window)))))
    (when (and aws-iam-role-viewer-fullscreen (window-live-p window))
      (select-window window)
      (delete-other-windows))))

(defun aws-iam-role-viewer-show-buffer (role)
  "Render IAM ROLE object and its policies in a new Org-mode buffer."
  (let* ((timestamp (format-time-string "%Y%m%d-%H%M%S"))
         (buf-name (format "*IAM Role: %s <%s>*"
                           (aws-iam-role-viewer-name role)
                           timestamp))
         (buf (get-buffer-create buf-name)))
    (aws-iam-role-viewer-populate-role-buffer role buf)
    (aws-iam-role-viewer-finalize-and-display-role-buffer buf)))
