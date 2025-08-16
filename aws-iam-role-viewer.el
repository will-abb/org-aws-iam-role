;;; aws-iam-role-viewer.el --- IAM Role and Policy object browser -*- lexical-binding: t; -*-

(require 'cl-lib)
(require 'json)
(require 'url-util)
(require 'async)
(require 'promise)
(require 'ob-shell)
(add-to-list 'org-babel-load-languages '(shell . t))

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

(defun aws-iam-role-viewer--cli-profile-arg ()
  "Return the AWS CLI profile argument string, or an empty string."
  (if aws-iam-role-viewer-profile
      (format " --profile %s" (shell-quote-argument aws-iam-role-viewer-profile))
    ""))

(defun aws-iam-role-viewer-check-auth ()
  "Ensure the user is authenticated with AWS. Raise error if not."
  (let* ((cmd (format "aws sts get-caller-identity --output json%s"
                      (aws-iam-role-viewer--cli-profile-arg)))
         (exit-code (shell-command cmd nil nil)))
    ;; A non-zero exit code from the AWS CLI indicates an error (e.g., bad credentials).
    (unless (eq exit-code 0)
      (user-error "AWS CLI not authenticated: please check your credentials or AWS_PROFILE"))))

(defun aws-iam-format-tags (tags)
  "Format AWS tags from a list of alists into a single JSON string."
  (when tags
    ;; AWS tags are a list of alists, e.g., '((Key . "k1") (Value . "v1")).
    ;; We simplify this to a single alist '(( "k1" . "v1" )) for easier JSON encoding.
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

(defun aws-iam-policy--construct-from-data (metadata policy-type document-json)
  "Construct an `aws-iam-policy' struct from resolved data.
METADATA is the parsed 'Policy' alist from `get-policy`.
POLICY-TYPE is the type symbol (e.g., 'aws-managed).
DOCUMENT-JSON is the raw JSON string from `get-policy-version`."
  (let* ((policy-version (alist-get 'PolicyVersion (json-parse-string document-json :object-type 'alist)))
         (document-string (alist-get 'Document policy-version))
         ;; The policy document itself is a URL-encoded JSON string inside the parent JSON.
         (document (when document-string
                     (if (stringp document-string)
                         (json-parse-string (url-unhex-string document-string) :object-type 'alist)
                       document-string))))
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
     :tags (alist-get 'Tags metadata))))

(defun aws-iam-policy-from-arn-async (policy-arn policy-type)
  "Create an `aws-iam-policy' struct asynchronously from a policy ARN.
Returns a promise that resolves with the complete `aws-iam-policy` struct."
  (promise-chain
      ;; Step 1: Fetch the policy metadata.
      (aws-iam-policy-get-metadata-async policy-arn)

    ;; Step 2: From metadata, fetch the policy document.
    (then (lambda (metadata-json)
            (let* ((metadata (alist-get 'Policy (json-parse-string metadata-json :object-type 'alist)))
                   (version-id (alist-get 'DefaultVersionId metadata)))
              (if version-id
                  (promise-then (aws-iam-policy-get-version-document-async policy-arn version-id)
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
                (aws-iam-policy--construct-from-data metadata policy-type document-json)))))

    ;; Step 4: Catch any promise rejection in the chain and resolve to nil.
    (catcha nil)))

(defun aws-iam-inline-policy--construct-from-json (policy-name json)
  "Construct an inline `aws-iam-policy' struct from its JSON representation.
POLICY-NAME is the name of the inline policy. JSON is the raw
string from the `get-role-policy` AWS CLI command."
  (let* ((parsed (json-parse-string json :object-type 'alist :array-type 'list))
         (document (alist-get 'PolicyDocument parsed))
         ;; The policy document is a URL-encoded JSON string inside the parent JSON.
         (decoded-doc (when document
                        (if (stringp document)
                            (json-parse-string (url-unhex-string document) :object-type 'alist :array-type 'list)
                          document))))
    (make-aws-iam-policy
     :name policy-name
     :policy-type 'inline
     :document decoded-doc)))

(defun aws-iam-inline-policy-from-name-async (role-name policy-name)
  "Fetch an inline policy asynchronously and construct an `aws-iam-policy' struct.
Returns a promise that resolves with the struct."
  (let* ((cmd (format "aws iam get-role-policy --role-name %s --policy-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (shell-quote-argument policy-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (start-func `(lambda () (shell-command-to-string ,cmd))))
    (promise-chain (promise:async-start start-func)
      (then (lambda (json)
              (aws-iam-inline-policy--construct-from-json policy-name json))))))


;;; IAM Role Data Functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun aws-iam-role-viewer--fetch-roles-page (marker)
  "Fetch a single page of IAM roles from AWS.
If MARKER is non-nil, it's used as the `--starting-token`.
Returns a cons cell: (LIST-OF-ROLES . NEXT-MARKER)."
  (let* ((cmd (format "aws iam list-roles --output json%s%s"
                      (aws-iam-role-viewer--cli-profile-arg)
                      (if marker
                          (format " --starting-token %s" (shell-quote-argument marker))
                        "")))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (cons (alist-get 'Roles parsed) (alist-get 'Marker parsed))))

(defun aws-iam-role-viewer-list-names ()
  "Return a list of all IAM role names, handling pagination."
  (let ((all-roles '())
        (marker nil)
        (first-run t))
    ;; Loop until the AWS API returns no more pages (i.e., the marker is nil).
    ;; The `first-run` flag ensures the loop runs at least once when marker starts as nil.
    (while (or first-run marker)
      (let* ((page-result (aws-iam-role-viewer--fetch-roles-page marker))
             (roles-on-page (car page-result))
             (next-marker (cdr page-result)))
        (setq all-roles (nconc all-roles roles-on-page))
        (setq marker next-marker)
        (setq first-run nil)))
    (mapcar (lambda (r) (alist-get 'RoleName r)) all-roles)))

(defun aws-iam-role-viewer-get-full (role-name)
  "Fetch full IAM role object from AWS using `get-role`."
  (let* ((cmd (format "aws iam get-role --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (shell-command-to-string cmd))
         (parsed (alist-get 'Role (json-parse-string json :object-type 'alist :array-type 'list))))
    parsed))

(defun aws-iam-role-viewer-construct (obj)
  "Create an `aws-iam-role-viewer` struct from a full `get-role` object."
  ;; PermissionsBoundary and RoleLastUsed can be nil, so we get them first.
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
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'AttachedPolicies parsed)))

(defun aws-iam-role-viewer-inline-policies (role-name)
  "Return list of inline policy names for ROLE-NAME."
  (let* ((cmd (format "aws iam list-role-policies --role-name %s --output json%s"
                      (shell-quote-argument role-name)
                      (aws-iam-role-viewer--cli-profile-arg)))
         (json (shell-command-to-string cmd))
         (parsed (json-parse-string json :object-type 'alist :array-type 'list)))
    (alist-get 'PolicyNames parsed)))

(defun aws-iam-role-viewer-split-managed-policies (attached)
  "Split ATTACHED managed policies into (customer . aws) buckets, keeping full alist per item."
  (let ((customer '()) (aws '()))
    (dolist (p attached)
      (let ((arn (alist-get 'PolicyArn p)))
        ;; AWS-managed policies have a standard, well-known ARN prefix.
        (if (string-prefix-p "arn:aws:iam::aws:policy/" arn)
            (push p aws)
          (push p customer))))
    (cons (nreverse customer) (nreverse aws))))


(defun org-babel-execute:aws-iam (body params)
  "Execute an aws-iam source block to update an IAM policy in AWS.
This function is called when the user presses C-c C-c inside an
aws-iam source block. It reads the block's content (the policy JSON)
and header arguments to construct and run the appropriate AWS CLI command."
  (let* ((role-name (cdr (assoc :role-name params)))
         (policy-name (cdr (assoc :policy-name params)))
         (policy-type-str (cdr (assoc :policy-type params)))
         (policy-type (intern policy-type-str))
         (policy-document body))

    (unless (and role-name policy-name policy-type)
      (user-error "Missing required header arguments: :role-name, :policy-name, or :policy-type"))

    (message "Updating IAM Policy '%s' for role '%s'..." policy-name role-name)

    ;; Prepare the policy document for the command line.
    ;; It needs to be a single-line JSON string.
    (let* ((json-string (json-encode (json-read-from-string policy-document)))
           (cmd (cond
                 ;; 1. Inline policies: use 'put-role-policy'.
                 ((eq policy-type 'inline)
                  (format "aws iam put-role-policy --role-name %s --policy-name %s --policy-document %s%s"
                          (shell-quote-argument role-name)
                          (shell-quote-argument policy-name)
                          (shell-quote-argument json-string)
                          (aws-iam-role-viewer--cli-profile-arg)))

                 ;; 2. Managed policies: create a new policy version.
                 ((or (eq policy-type 'customer-managed) (eq policy-type 'aws-managed))
                  (let ((policy-arn (cdr (assoc :arn params))))
                    (unless policy-arn
                      (user-error "Missing required header argument for managed policy: :arn"))
                    (format "aws iam create-policy-version --policy-arn %s --policy-document %s --set-as-default%s"
                            (shell-quote-argument policy-arn)
                            (shell-quote-argument json-string)
                            (aws-iam-role-viewer--cli-profile-arg))))

                 ;; 3. Permissions Boundary: is a managed policy.
                 ((eq policy-type 'permissions-boundary)
                  (let ((policy-arn (cdr (assoc :arn params))))
                    (unless policy-arn
                      (user-error "Missing required header argument for boundary policy: :arn"))
                    (format "aws iam create-policy-version --policy-arn %s --policy-document %s --set-as-default%s"
                            (shell-quote-argument policy-arn)
                            (shell-quote-argument json-string)
                            (aws-iam-role-viewer--cli-profile-arg))))

                 (t (user-error "Unsupported policy type for modification: %s" policy-type)))))
      ;; Execute the command asynchronously to avoid freezing Emacs.
      (async-shell-command cmd "*AWS IAM Update Output*")
      (message "Policy update command sent to AWS for '%s'." policy-name))))

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
  ;; Use "nil" as a string for display if the actual value is nil.
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
      ;; Don't let a JSON formatting error stop buffer creation.
      (condition-case e
          (json-pretty-print start (point))
        (error nil)))
    (insert "\n#+END_SRC\n")))

(defun aws-iam-role-viewer--format-policy-type (policy-type-symbol)
  "Format the policy type symbol into a human-readable string."
  (cond ((eq policy-type-symbol 'aws-managed) "AWS Managed")
        ((eq policy-type-symbol 'customer-managed) "Customer Managed")
        ((eq policy-type-symbol 'inline) "Inline")
        ((eq policy-type-symbol 'permissions-boundary) "Permissions Boundary")
        (t (capitalize (symbol-name policy-type-symbol)))))

(defun aws-iam-role-viewer--insert-policy-struct-details (policy role-name)
  "Insert the details of a pre-fetched `aws-iam-policy' struct into the buffer."
  (let* ((doc-json (json-encode (aws-iam-policy-document policy)))
         (policy-type-symbol (aws-iam-policy-policy-type policy))
         (policy-arn (or (aws-iam-policy-arn policy) "")))
    (insert (format "*** %s\n" (aws-iam-policy-name policy)))
    (insert ":PROPERTIES:\n")
    (insert (format ":AWSPolicyType: %s\n" (aws-iam-role-viewer--format-policy-type policy-type-symbol)))
    (insert (format ":ID: %s\n" (or (aws-iam-policy-id policy) "nil")))
    (insert (format ":ARN: %s\n" (or policy-arn "nil")))
    (insert (format ":Path: %s\n" (or (aws-iam-policy-path policy) "nil")))
    (insert (format ":Description: %s\n" (or (aws-iam-policy-description policy) "nil")))
    (insert (format ":Created: %s\n" (or (aws-iam-policy-create-date policy) "nil")))
    (insert (format ":Updated: %s\n" (or (aws-iam-policy-update-date policy) "nil")))
    (insert (format ":AttachmentCount: %s\n" (or (aws-iam-policy-attachment-count policy) "nil")))
    (insert (format ":DefaultVersion: %s\n" (or (aws-iam-policy-default-version-id policy) "nil")))
    (insert ":END:\n")
    (insert "Policy Document (C-c C-c to apply changes):\n")

    (insert (format "#+BEGIN_SRC aws-iam :role-name \"%s\" :policy-name \"%s\" :policy-type \"%s\" :arn \"%s\"\n"
                    role-name
                    (aws-iam-policy-name policy)
                    (symbol-name policy-type-symbol)
                    policy-arn))
    (let ((start (point)))
      (insert doc-json)
      (condition-case e
          (json-pretty-print start (point))
        (error nil)))
    (insert "\n#+END_SRC\n")))

(defun aws-iam-role-viewer--insert-remaining-sections-and-finalize (role buf)
  "Insert remaining sync sections and finalize buffer display."
  (with-current-buffer buf
    (aws-iam-role-viewer-insert-trust-policy role))
  (aws-iam-role-viewer-finalize-and-display-role-buffer buf))

(defun aws-iam-role-viewer--get-all-policies-async (role)
  "Fetch all attached, inline, and boundary policies for ROLE.
This function is asynchronous and returns a single promise that
resolves with a vector of `aws-iam-policy' structs when all
underlying fetches are complete. Returns nil if no policies
are found."
  (let* ((role-name (aws-iam-role-viewer-name role))
         ;; 1. Get lists of all policy identifiers first
         (attached (aws-iam-role-viewer-attached-policies role-name))
         (split (aws-iam-role-viewer-split-managed-policies attached))
         (customer-managed (car split))
         (aws-managed (cdr split))
         (inline-policy-names (aws-iam-role-viewer-inline-policies role-name))
         (boundary-arn (aws-iam-role-viewer-permissions-boundary-arn role))

         ;; 2. Create a unified list of promises for ALL policy types
         (aws-promises (mapcar (lambda (p) (aws-iam-policy-from-arn-async (alist-get 'PolicyArn p) 'aws-managed)) aws-managed))
         (customer-promises (mapcar (lambda (p) (aws-iam-policy-from-arn-async (alist-get 'PolicyArn p) 'customer-managed)) customer-managed))
         (boundary-promise (when boundary-arn (list (aws-iam-policy-from-arn-async boundary-arn 'permissions-boundary))))
         (inline-promises (mapcar (lambda (name) (aws-iam-inline-policy-from-name-async role-name name)) inline-policy-names))
         (all-promises (append aws-promises customer-promises boundary-promise inline-promises)))
    ;; Only create a master promise if there are any child promises to run.
    (when all-promises
      (promise-all all-promises))))

(defun aws-iam-role-viewer--insert-policies-section (all-policies-vector boundary-arn role-name)
  "Render a vector of fetched policies into the current buffer.
ALL-POLICIES-VECTOR is the result from a `promise-all' call.
BOUNDARY-ARN is the original ARN of the boundary policy, used
to determine if the section header should be rendered."
  (let* ((policies-list (seq-into all-policies-vector 'list))
         ;; Filter out any nil results from promises that may have failed gracefully.
         (valid-policies (cl-remove-if-not #'identity policies-list))
         ;; Separate boundary policy from the rest for individual rendering.
         (boundary-policy (cl-find 'permissions-boundary valid-policies :key #'aws-iam-policy-policy-type))
         (permission-policies (cl-remove 'permissions-boundary valid-policies :key #'aws-iam-policy-policy-type)))

    ;; 1. Render Permission Policies (AWS, Customer, Inline)
    (insert "** Permission Policies\n")
    (if permission-policies
        (dolist (p permission-policies) (aws-iam-role-viewer--insert-policy-struct-details p role-name))
      (insert "nil\n"))

    ;; 2. Render Permissions Boundary Policy
    (when boundary-arn
      (insert "** Permissions Boundary Policy\n")
      (if boundary-policy
          (aws-iam-role-viewer--insert-policy-struct-details boundary-policy role-name)
        (insert "Failed to fetch permissions boundary policy.\n")))))

(defun aws-iam-role-viewer-populate-role-buffer (role buf)
  "Insert all role details and policies into the buffer BUF.
This function orchestrates the asynchronous fetching and
rendering of role information."
  (with-current-buffer buf
    (erase-buffer)
    (org-mode)
    (aws-iam-role-viewer-insert-role-header role)
    (insert "\n;; --- Keybinds --- \n")
    (insert ";; C-c C-h : Hide all property drawers\n")
    (insert ";; C-c C-r : Reveal all property drawers\n\n"))

  ;; Asynchronously fetch all policies for the role.
  (let ((policies-promise (aws-iam-role-viewer--get-all-policies-async role))
        (boundary-arn (aws-iam-role-viewer-permissions-boundary-arn role))
        (role-name (aws-iam-role-viewer-name role)))
    ;; If there are policies, wait for them and then render. Otherwise, render the empty state.
    (if policies-promise
        (promise-then
         policies-promise
         (lambda (all-policies-vector)
           ;; Catch any error during rendering to prevent the callback from crashing Emacs.
           (condition-case e
               (with-current-buffer buf
                 ;; Insert the fetched policy sections.
                 (aws-iam-role-viewer--insert-policies-section all-policies-vector boundary-arn role-name)
                 ;; Insert remaining synchronous sections and finalize the buffer.
                 (aws-iam-role-viewer--insert-remaining-sections-and-finalize role buf))
             (error nil))))
      ;; Case where there are no policies of any kind.
      (with-current-buffer buf
        (insert "** Permission Policies\n")
        (insert "nil\n")
        (aws-iam-role-viewer--insert-remaining-sections-and-finalize role buf)))))

(defun aws-iam-role-viewer-finalize-and-display-role-buffer (buf)
  "Set keybinds, mode, and display the buffer BUF."
  (with-current-buffer buf
    (local-set-key (kbd "C-c C-h") #'org-fold-hide-drawer-all)
    (local-set-key (kbd "C-c C-r") #'org-fold-show-all)
    (goto-char (point-min))
    (if aws-iam-role-viewer-show-folded-by-default
        (org-overview)
      (org-fold-show-all)))
  ;; Display in a pop-up window.
  (let ((window (display-buffer buf '((display-buffer-pop-up-window)))))
    ;; If fullscreen is enabled, make this the only window.
    (when (and aws-iam-role-viewer-fullscreen (window-live-p window))
      (select-window window)
      (delete-other-windows))))

(defun aws-iam-role-viewer-show-buffer (role)
  "Render IAM ROLE object and its policies in a new Org-mode buffer."
  (let* ((timestamp (format-time-string "%Y%m%d-%H%M%S"))
         ;; Add a timestamp to the buffer name to ensure uniqueness for multiple views.
         (buf-name (format "*IAM Role: %s <%s>*"
                           (aws-iam-role-viewer-name role)
                           timestamp))
         (buf (get-buffer-create buf-name)))
    (aws-iam-role-viewer-populate-role-buffer role buf)))

(provide 'aws-iam-role-viewer)
;;; aws-iam-role-viewer.el ends here
