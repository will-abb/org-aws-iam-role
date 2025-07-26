;;; iam-role-viewer.el --- IAM Role and Policy object browser -*- lexical-binding: t; -*-

(require 'cl-lib)
(require 'json)
(require 'url-util)
(require 'async)
(require 'promise)
(require 'log4e)

(defvar aws-iam-role-viewer-profile nil
  "Default AWS CLI profile to use for IAM role operations.
If nil, uses default profile or environment credentials.")

(defvar aws-iam-role-viewer-show-folded-by-default nil
  "If non-nil, show the role detail buffer with all sections folded.")

(defvar aws-iam-role-viewer-fullscreen t
  "If non-nil, show the IAM role buffer in fullscreen.")

(defvar aws-iam-role-viewer-log-level 'debug
  "The logging level for the IAM Role Viewer.
Set this to 'debug, 'info, 'warn, 'error, or 'fatal.
Default is 'debug.")

(log4e:deflogger "aws-iam-role-viewer" "%t [%l] %m" "%Y-%m-%d %H:%M:%S")

(defun aws-iam-role-viewer--init-logger ()
  "Initialize the package logger based on `aws-iam-role-viewer-log-level`."
  (aws-iam-role-viewer--log-enable-logging)
  (aws-iam-role-viewer--log-enable-messaging)
  (aws-iam-role-viewer--log-set-level aws-iam-role-viewer-log-level 'fatal))

(aws-iam-role-viewer--init-logger)


;;;###autoload
(defun aws-iam-role-viewer-view-details ()
  "Prompt for an IAM role and display its details in an Org-mode buffer."
  (interactive)
  (aws-iam-role-viewer-check-auth)
  (let* ((name (completing-read "IAM Role: " (aws-iam-role-viewer-list-names)))
         (role (aws-iam-role-viewer-construct
                (aws-iam-role-viewer-get-full name))))
    (aws-iam-role-viewer--log-info "Viewing details for role: %s" name)
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

(defun aws-iam-role-viewer--cli-profile-arg ()
  "Return the AWS CLI profile argument string, or an empty string."
  (if aws-iam-role-viewer-profile
      (format " --profile %s" (shell-quote-argument aws-iam-role-viewer-profile))
    ""))

(defun aws-iam-role-viewer-check-auth ()
  "Ensure the user is authenticated with AWS. Raise error if not."
  (let* ((cmd (format "aws sts get-caller-identity --output json%s"
                      (aws-iam-role-viewer--cli-profile-arg)))
         (exit-code (progn
                      (aws-iam-role-viewer--log-debug "Executing auth check: %s" cmd)
                      (shell-command cmd nil nil))))
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

(defun aws-iam-policy-get-metadata-async (policy-arn)
  "Fetch policy metadata JSON asynchronously from AWS using `get-policy`.
Returns a promise that resolves with the raw JSON string."
  (let* ((cmd (format "aws iam get-policy --policy-arn %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise:async-start start-func)))

(defun aws-iam-policy-get-version-document-async (policy-arn version-id)
  "Fetch policy document JSON asynchronously using `get-policy-version`.
Returns a promise that resolves with the raw JSON string."
  (let* ((cmd (format "aws iam get-policy-version --policy-arn %s --version-id %s --output json%s"
                      (shell-quote-argument policy-arn)
                      (shell-quote-argument version-id)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise:async-start start-func)))

(defun aws-iam-policy-from-arn-async (policy-arn policy-type)
  "Create an `aws-iam-policy' struct asynchronously from a policy ARN.
Returns a promise that resolves with the complete `aws-iam-policy` struct."
  (promise-chain (aws-iam-policy-get-metadata-async policy-arn)
    ;; Step 1: Receive and parse the metadata JSON
    (then (lambda (metadata-json)
            (aws-iam-role-viewer--log-debug "Parsing metadata JSON for %s" policy-arn)
            (let* ((metadata (alist-get 'Policy (json-parse-string metadata-json :object-type 'alist)))
                   (version-id (alist-get 'DefaultVersionId metadata)))
              (if version-id
                  (promise-then (aws-iam-policy-get-version-document-async policy-arn version-id)
                                (lambda (document-json)
                                  (list metadata document-json))) ; Pass both results
                (promise-resolve (list metadata :error))))))

    ;; Step 2: Receive the results of Step 1 and build the final struct.
    (then (lambda (results)
            (let ((metadata (car results))
                  (second-part (cadr results)))
              (if (eq second-part :error)
                  (progn
                    (aws-iam-role-viewer--log-error "Could not get version-id from metadata for ARN: %s" policy-arn)
                    nil)
                (let* ((document-json second-part)
                       (policy-version (alist-get 'PolicyVersion (json-parse-string document-json :object-type 'alist)))
                       (document-string (alist-get 'Document policy-version))
                       (document (when document-string
                                   (if (stringp document-string)
                                       (json-parse-string (url-unhex-string document-string) :object-type 'alist)
                                     document-string))))
                  (aws-iam-role-viewer--log-debug "Successfully parsed document for %s" policy-arn)
                  (make-aws-iam-policy
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
                   :tags (alist-get 'Tags metadata)))))))

    ;; Catch any failure anywhere in the chain above.
    (catcha
     (progn
       (aws-iam-role-viewer--log-error "--- PROMISE CHAIN FAILED ---")
       (aws-iam-role-viewer--log-error "ARN: %s" policy-arn)
       (aws-iam-role-viewer--log-error "REASON TYPE: %s" (type-of reason))
       (aws-iam-role-viewer--log-error "REASON (safe): %s" (ignore-errors (format "%S" reason)))
       (aws-iam-role-viewer--log-error "--- END OF FAILURE REPORT ---"))
     nil)))


;;; IAM Role Data Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer-list-names ()
  "Return a list of IAM role names using `list-roles`."
  (let ((all-roles '())
        (marker nil)
        (first-run t))
    (while (or first-run marker)
      (let* ((cmd (format "aws iam list-roles --output json%s%s"
                          (aws-iam-role-viewer--cli-profile-arg)
                          (if marker
                              (format " --starting-token %s" (shell-quote-argument marker))
                            "")))
             (json (progn
                     (aws-iam-role-viewer--log-debug "Executing command: %s" cmd)
                     (shell-command-to-string cmd)))
             (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
        (setq all-roles (nconc all-roles (alist-get 'Roles parsed)))
        (setq marker (alist-get 'Marker parsed))
        (setq first-run nil)))
    (mapcar (lambda (r) (alist-get 'RoleName r)) all-roles)))

(defun aws-iam-role-viewer-get-full (role-name)
  "Fetch full IAM role object from AWS using `get-role`."
  (let* ((cmd (format "aws iam get-role --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (progn
                 (aws-iam-role-viewer--log-debug "Executing command: %s" cmd)
                 (shell-command-to-string cmd)))
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
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (progn
                 (aws-iam-role-viewer--log-debug "Executing command: %s" cmd)
                 (shell-command-to-string cmd)))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'AttachedPolicies parsed)))

(defun aws-iam-role-viewer-inline-policies (role-name)
  "Return list of inline policy names for ROLE-NAME."
  (let* ((cmd (format "aws iam list-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (progn
                 (aws-iam-role-viewer--log-debug "Executing command: %s" cmd)
                 (shell-command-to-string cmd)))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'PolicyNames parsed)))

(defun aws-iam-role-viewer-get-inline-policy-document (role-name policy-name)
  "Fetch and decode an inline policy document for a role."
  (let* ((cmd (format "aws iam get-role-policy --role-name %s --policy-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (shell-quote-argument policy-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (progn
                 (aws-iam-role-viewer--log-debug "Executing command: %s" cmd)
                 (shell-command-to-string cmd)))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list))
         (document (alist-get 'PolicyDocument parsed)))
    (when document
      (if (stringp document)
          (json-parse-string (url-unhex-string document) :object-type 'alist :array-type 'list)
        document))))

(defun aws-iam-role-viewer-create-inline-policy-struct (role-name policy-name)
  "Fetch an inline policy and construct an `aws-iam-policy' struct for it."
  (aws-iam-role-viewer--log-debug "Creating inline policy struct for: %s" policy-name)
  (let ((doc (aws-iam-role-viewer-get-inline-policy-document role-name policy-name)))
    (make-aws-iam-policy
     :name policy-name
     :policy-type 'inline
     :document doc)))

(defun aws-iam-role-viewer-split-managed-policies (attached)
  "Split ATTACHED managed policies into (customer . aws) buckets, keeping full alist per item."
  (let ((customer '()) (aws '()))
    (dolist (p attached)
      (let ((arn (alist-get 'PolicyArn p)))
        (if (string-prefix-p "arn:aws:iam::aws:policy/" arn)
            (push p aws)
          (push p customer))))
    (cons (nreverse customer) (nreverse aws))))


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
  (aws-iam-role-viewer--log-debug "--> ENTERING insert-trust-policy")
  (let ((trust-policy-json (json-encode (aws-iam-role-viewer-trust-policy role))))
    (insert "** Trust Policy\n")
    (insert "#+BEGIN_SRC json\n")
    (let ((start (point)))
      (insert trust-policy-json)
      (condition-case e
          (json-pretty-print start (point))
        (error
         (aws-iam-role-viewer--log-warn "Could not pretty-print trust policy JSON: %S" e))))
    (insert "\n#+END_SRC\n"))
  (aws-iam-role-viewer--log-debug "<-- LEAVING insert-trust-policy"))

(defun aws-iam-role-viewer--format-policy-type (policy-type-symbol)
  "Format the policy type symbol into a human-readable string."
  (cond ((eq policy-type-symbol 'aws-managed) "AWS Managed")
        ((eq policy-type-symbol 'customer-managed) "Customer Managed")
        ((eq policy-type-symbol 'inline) "Inline")
        ((eq policy-type-symbol 'permissions-boundary) "Permissions Boundary")
        (t (capitalize (symbol-name policy-type-symbol)))))

(defun aws-iam-role-viewer--insert-policy-struct-details (policy)
  "Insert the details of a pre-fetched `aws-iam-policy' struct into the buffer."
  (aws-iam-role-viewer--log-debug "--> ENTERING insert-policy-struct-details for: %s" (aws-iam-policy-name policy))
  (let ((doc-json (json-encode (aws-iam-policy-document policy))))
    (aws-iam-role-viewer--log-debug "     ... inserting header")
    (insert (format "*** %s\n" (aws-iam-policy-name policy)))
    (aws-iam-role-viewer--log-debug "     ... inserting props block")
    (insert ":PROPERTIES:\n")
    (aws-iam-role-viewer--log-debug "     ... inserting AWSPolicyType")
    (insert (format ":AWSPolicyType: %s\n" (aws-iam-role-viewer--format-policy-type (aws-iam-policy-policy-type policy))))
    (aws-iam-role-viewer--log-debug "     ... inserting ID")
    (insert (format ":ID: %s\n" (or (aws-iam-policy-id policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting ARN")
    (insert (format ":ARN: %s\n" (or (aws-iam-policy-arn policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting Path")
    (insert (format ":Path: %s\n" (or (aws-iam-policy-path policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting Description")
    (insert (format ":Description: %s\n" (or (aws-iam-policy-description policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting Created")
    (insert (format ":Created: %s\n" (or (aws-iam-policy-create-date policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting Updated")
    (insert (format ":Updated: %s\n" (or (aws-iam-policy-update-date policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting AttachmentCount")
    (insert (format ":AttachmentCount: %s\n" (or (aws-iam-policy-attachment-count policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting DefaultVersion")
    (insert (format ":DefaultVersion: %s\n" (or (aws-iam-policy-default-version-id policy) "nil")))
    (aws-iam-role-viewer--log-debug "     ... inserting END")
    (insert ":END:\n")
    (aws-iam-role-viewer--log-debug "     ... inserting doc header")
    (insert "Policy Document:\n")
    (insert "#+BEGIN_SRC json\n")
    (let ((start (point)))
      (aws-iam-role-viewer--log-debug "     ... inserting doc json")
      (insert doc-json)
      (aws-iam-role-viewer--log-debug "     ... pretty-printing json")
      (condition-case e
          (json-pretty-print start (point))
        (error
         (aws-iam-role-viewer--log-warn "Could not pretty-print policy document JSON: %S" e))))
    (aws-iam-role-viewer--log-debug "     ... inserting end src")
    (insert "\n#+END_SRC\n"))
  (aws-iam-role-viewer--log-debug "<-- LEAVING insert-policy-struct-details for: %s" (aws-iam-policy-name policy)))

(defun aws-iam-role-viewer--insert-remaining-sections-and-finalize (role buf)
  "Insert remaining sync sections and finalize buffer display."
  (aws-iam-role-viewer--log-debug "--> ENTERING insert-remaining-sections-and-finalize")
  (with-current-buffer buf
    (aws-iam-role-viewer-insert-trust-policy role))
  (aws-iam-role-viewer-finalize-and-display-role-buffer buf)
  (aws-iam-role-viewer--log-debug "<-- LEAVING insert-remaining-sections-and-finalize"))

(defun aws-iam-role-viewer-populate-role-buffer (role buf)
  "Insert all role details and policies into the buffer BUF."
  (with-current-buffer buf
    (erase-buffer)
    (org-mode)
    (aws-iam-role-viewer-insert-role-header role)
    (insert "\n;; --- Keybinds --- \n")
    (insert ";; C-c C-h : Hide all property drawers\n")
    (insert ";; C-c C-r : Reveal all property drawers\n\n")

    ;; --- Unified Policy Fetching ---
    (let* ((role-name (aws-iam-role-viewer-name role))
           ;; 1. Get ARNs/names for all policy types
           (attached (aws-iam-role-viewer-attached-policies role-name))
           (split (aws-iam-role-viewer-split-managed-policies attached))
           (customer-managed (car split))
           (aws-managed (cdr split))
           (inline-policy-names (aws-iam-role-viewer-inline-policies role-name))
           (boundary-arn (aws-iam-role-viewer-permissions-boundary-arn role))

           ;; 2. Create promises for all managed policies that need async fetching
           (aws-promises (mapcar (lambda (p) (aws-iam-policy-from-arn-async (alist-get 'PolicyArn p) 'aws-managed)) aws-managed))
           (customer-promises (mapcar (lambda (p) (aws-iam-policy-from-arn-async (alist-get 'PolicyArn p) 'customer-managed)) customer-managed))
           (boundary-promise (when boundary-arn (list (aws-iam-policy-from-arn-async boundary-arn 'permissions-boundary))))
           (all-promises (append aws-promises customer-promises boundary-promise))

           ;; 3. Create structs for inline policies (synchronous)
           (inline-policy-structs (mapcar (lambda (name) (aws-iam-role-viewer-create-inline-policy-struct role-name name)) inline-policy-names)))

      (if all-promises
          ;; Case 1: There are managed policies to fetch asynchronously
          (promise-then
           (promise-all all-promises)
           (lambda (managed-policies-vector)
             (condition-case e
                 (progn
                   (aws-iam-role-viewer--log-debug "Final promise callback entered for managed policies.")
                   (with-current-buffer buf
                     (let* ((managed-policies-list (seq-into managed-policies-vector 'list))
                            (valid-managed-policies (cl-remove-if-not #'identity managed-policies-list))
                            ;; Separate boundary policy from the rest
                            (boundary-policy (cl-find 'permissions-boundary valid-managed-policies :key #'aws-iam-policy-policy-type))
                            (regular-managed-policies (cl-remove 'permissions-boundary valid-managed-policies :key #'aws-iam-policy-policy-type))
                            (all-permission-policies (append regular-managed-policies inline-policy-structs)))

                       ;; 1. Render Permission Policies (AWS, Customer, Inline)
                       (insert "** Permission Policies\n")
                       (if all-permission-policies
                           (progn
                             (aws-iam-role-viewer--log-debug "Rendering %d permission policies." (length all-permission-policies))
                             (dolist (p all-permission-policies) (aws-iam-role-viewer--insert-policy-struct-details p)))
                         (insert "nil\n"))

                       ;; 2. Render Permissions Boundary Policy
                       (when boundary-arn
                         (insert "** Permissions Boundary Policy\n")
                         (if boundary-policy
                             (progn
                               (aws-iam-role-viewer--log-debug "Rendering permissions boundary policy.")
                               (aws-iam-role-viewer--insert-policy-struct-details boundary-policy))
                           (insert "Failed to fetch permissions boundary policy.\n")))

                       ;; 3. Render remaining sections (Trust Policy) and finalize
                       (aws-iam-role-viewer--insert-remaining-sections-and-finalize role buf))))
               (error
                (aws-iam-role-viewer--log-error "!!!!!! UNCAUGHT CRITICAL ERROR IN FINAL CALLBACK !!!!!!")
                (aws-iam-role-viewer--log-error "Error: %S" e)))))
        ;; Case 2: No managed policies, only inline (or none at all)
        (progn
          (aws-iam-role-viewer--log-debug "No managed policies to fetch. Processing inline policies only.")
          (with-current-buffer buf
            (insert "** Permission Policies\n")
            (if inline-policy-structs
                (progn
                  (aws-iam-role-viewer--log-debug "Rendering %d inline policies." (length inline-policy-structs))
                  (dolist (p inline-policy-structs) (aws-iam-role-viewer--insert-policy-struct-details p)))
              (insert "nil\n"))
            ;; Permissions boundary can't exist without managed policies, but trust policy still needs to be rendered.
            (aws-iam-role-viewer--insert-remaining-sections-and-finalize role buf)))))))

(defun aws-iam-role-viewer-show-all-drawers ()
  "Show all drawers in Org buffer using org-fold."
  (interactive)
  (org-fold-show-all))

(defun aws-iam-role-viewer-finalize-and-display-role-buffer (buf)
  "Set keybinds, mode, and display the buffer BUF."
  (aws-iam-role-viewer--log-debug "--> ENTERING finalize-and-display-role-buffer")
  (with-current-buffer buf
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
      (delete-other-windows)))
  (aws-iam-role-viewer--log-debug "<-- LEAVING finalize-and-display-role-buffer"))

(defun aws-iam-role-viewer-show-buffer (role)
  "Render IAM ROLE object and its policies in a new Org-mode buffer."
  (let* ((timestamp (format-time-string "%Y%m%d-%H%M%S"))
         (buf-name (format "*IAM Role: %s <%s>*"
                           (aws-iam-role-viewer-name role)
                           timestamp))
         (buf (get-buffer-create buf-name)))
    (aws-iam-role-viewer-populate-role-buffer role buf)))

(provide 'iam-role-viewer)
;;; iam-role-viewer.el ends here
