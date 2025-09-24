;;; org-aws-iam-role-simulate.el --- Policy simulation for org-aws-iam-role -*- lexical-binding: t; -*-

;; Copyright (C) 2025 William Bosch-Bello

;; Author: William Bosch-Bello <williamsbosch@gmail.com>
;; Maintainer: William Bosch-Bello <williamsbosch@gmail.com>
;; Created: August 16, 2025
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is part of the org-aws-iam-role package.
;; For version and dependency information, see org-aws-iam-role.el.

(require 'json)
(require 'org-aws-iam-role)

(defvar-local org-aws-iam-role--last-simulate-result nil
  "Hold the raw JSON string from the last IAM simulate-principal-policy run.")

(defvar-local org-aws-iam-role--last-simulate-role nil
  "Hold the last IAM Role ARN used for simulate-principal-policy.")

(defun org-aws-iam-role-simulate-from-buffer ()
  "Run a policy simulation using the ARN from the current role buffer."
  (interactive)
  (save-excursion
    (goto-char (point-min))
    (if (re-search-forward "^:ARN:[ \t]+\\(arn:aws:iam::.*\\)$" nil t)
        (org-aws-iam-role-simulate (match-string 1))
      (user-error "Could not find a valid Role ARN in this buffer"))))

(defun org-aws-iam-role-simulate (&optional role-arn)
  "Run a policy simulation for ROLE-ARN."
  (interactive)
  (let* ((role-arn (or role-arn
                       (let* ((roles (org-aws-iam-role-list-names))
                              (role-name (completing-read "IAM Role: " roles)))
                         (org-aws-iam-role-arn
                          (org-aws-iam-role-construct
                           (org-aws-iam-role-get-full role-name)))))))
    (setq org-aws-iam-role--last-simulate-role role-arn)
    (org-aws-iam-role-simulate-policy-for-arn role-arn)))

(defun org-aws-iam-role-rerun-simulation ()
  "Re-run a simulation using the last stored role ARN."
  (interactive)
  (if org-aws-iam-role--last-simulate-role
      (org-aws-iam-role-simulate org-aws-iam-role--last-simulate-role)
    (org-aws-iam-role-simulate)))

(defun org-aws-iam-role-simulate-policy-for-arn (role-arn)
  "Simulate the policy for ROLE-ARN after prompting for actions and resources."
  (let* ((actions-str (read-string "Action(s) to test (e.g., s3:ListObjects s3:Put*): "))
         (resources-str (read-string "Resource ARN(s) (e.g., arn:aws:s3:::my-bucket/*): "))
         (action-args (mapconcat #'shell-quote-argument (split-string actions-str nil t " +") " "))
         (resource-args (if (string-empty-p resources-str)
                            ""
                          (concat " --resource-arns "
                                  (mapconcat #'shell-quote-argument (split-string resources-str nil t " +") " "))))
         (cmd (format "aws iam simulate-principal-policy --policy-source-arn %s --action-names %s%s --output json%s"
                      (shell-quote-argument role-arn)
                      action-args
                      resource-args
                      (org-aws-iam-role--cli-profile-arg)))
         (json (or (shell-command-to-string cmd) ""))
         (results (condition-case nil
                      (alist-get 'EvaluationResults
                                 (json-parse-string json :object-type 'alist :array-type 'list))
                    (error nil))))
    ;; Create result buffer and save locals there
    (let* ((role-name (car (last (split-string role-arn "/"))))
           (timestamp (format-time-string "%Y%m%d-%H%M%S"))
           (buf (get-buffer-create
                 (format "*IAM Simulation: %s <%s>*" role-name timestamp))))
      (with-current-buffer buf
        (setq-local org-aws-iam-role--last-simulate-role role-arn)
        (setq-local org-aws-iam-role--last-simulate-result json))
      (org-aws-iam-role-show-simulation-result results))))

(defun org-aws-iam-role-show-simulation-result (results-list &optional raw-json)
  "Display the detailed RESULTS-LIST of a policy simulation in a new buffer.
Optional argument RAW-JSON is unused and reserved for future extensions."
  (let* ((role-name (if org-aws-iam-role--last-simulate-role
                        (car (last (split-string org-aws-iam-role--last-simulate-role "/")))
                      "unknown-role"))
         (timestamp (format-time-string "%Y%m%d-%H%M%S"))
         (buf-name (format "*IAM Simulation: %s <%s>*" role-name timestamp))
         (buf (get-buffer-create buf-name)))
    (with-current-buffer buf
      (erase-buffer)
      (insert (propertize "Press C-c C-j to view raw JSON output\n" 'face 'font-lock-comment-face))
      (insert (propertize "Press C-c C-c to rerun the simulation for the last role\n\n" 'face 'font-lock-comment-face))
      (insert (propertize "Full list of AWS actions: " 'face 'font-lock-comment-face))
      (insert-button
       "Service Authorization Reference"
       'action (lambda (_)
                 (browse-url
                  "https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html"))
       'follow-link t
       'face 'link)
      (insert "\n\n")
      (org-aws-iam-role-insert-simulation-warning)
      (unless results-list
        (insert (propertize "No simulation results returned. Check the AWS CLI command for errors"
                            'face 'error))
        (pop-to-buffer buf)
        (cl-return-from org-aws-iam-role-show-simulation-result))
      (dolist (result-item results-list)
        (org-aws-iam-role-insert-one-simulation-result result-item))
      (goto-char (point-min))
      (use-local-map (copy-keymap special-mode-map))
      (local-set-key (kbd "C-c C-j") #'org-aws-iam-role-show-raw-json)
      (local-set-key (kbd "C-c C-c") #'org-aws-iam-role-rerun-simulation)
      (pop-to-buffer buf))))

(defun org-aws-iam-role-show-raw-json ()
  "Show the raw JSON from the last IAM simulation."
  (interactive)
  (let* ((sim-buf (cl-find-if
                   (lambda (b)
                     (with-current-buffer b
                       (bound-and-true-p org-aws-iam-role--last-simulate-result)))
                   (buffer-list)))
         (json (and sim-buf
                    (buffer-local-value 'org-aws-iam-role--last-simulate-result sim-buf)))
         (role-arn (and sim-buf
                        (buffer-local-value 'org-aws-iam-role--last-simulate-role sim-buf))))
    (if (not (and json (stringp json) (not (string-empty-p json))))
        (user-error "No JSON stored from last simulation")
      (let* ((role-name (if role-arn
                            (car (last (split-string role-arn "/")))
                          "unknown-role"))
             (timestamp (format-time-string "%Y%m%d-%H%M%S"))
             (buf (get-buffer-create
                   (format "*IAM Simulate JSON: %s <%s>*" role-name timestamp))))
        (with-current-buffer buf
          (erase-buffer)
          (insert json)
          (condition-case nil
              (json-pretty-print-buffer)
            (error (message "Warning: could not pretty-print JSON")))
          (goto-char (point-min))
          (when (fboundp 'json-mode)
            (json-mode)))
        (pop-to-buffer buf)))))

(defun org-aws-iam-role-insert-one-simulation-result (result-item)
  "Insert the formatted details for a single simulation RESULT-ITEM."
  (let ((parsed-result (org-aws-iam-role-parse-simulation-result-item result-item)))
    (org-aws-iam-role-insert-parsed-simulation-result parsed-result)))

(defun org-aws-iam-role-insert-parsed-simulation-result (parsed-result)
  "Insert a PARSED-RESULT plist into the current buffer."
  (insert (propertize "====================================\n" 'face 'shadow))
  (insert (propertize "Action: " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :action) 'face 'font-lock-function-name-face))
  (insert "\n")
  (insert (propertize "------------------------------------\n" 'face 'shadow))
  (insert (propertize "Decision:           " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :decision) 'face (plist-get parsed-result :decision-face)))
  (insert "\n")
  (insert (propertize "Resource:           " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :resource) 'face 'shadow))
  (insert "\n")
  (insert (propertize "Boundary Allowed: " 'face 'font-lock-keyword-face))
  (let ((pb (plist-get parsed-result :pb-allowed)))
    (insert (propertize (if pb "true" "false") 'face (if pb 'success 'error))))
  (insert "\n")
  (insert (propertize "Org Allowed:      " 'face 'font-lock-keyword-face))
  (let ((org (plist-get parsed-result :org-allowed)))
    (insert (propertize (if org "true" "false") 'face (if org 'success 'error))))
  (insert "\n")
  (insert (propertize "Matched Policies: " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :policy-ids-str) 'face 'shadow))
  (insert "\n")
  (insert (propertize "Missing Context:  " 'face 'font-lock-keyword-face))
  (insert (propertize (plist-get parsed-result :missing-context-str) 'face 'shadow))
  (insert "\n\n"))

(defun org-aws-iam-role-parse-simulation-result-item (result-item)
  "Parse RESULT-ITEM from simulation into a plist for display."
  (let* ((decision (alist-get 'EvalDecision result-item))
         (pb-detail (alist-get 'PermissionsBoundaryDecisionDetail result-item))
         (org-detail (alist-get 'OrganizationsDecisionDetail result-item))
         (matched-statements (alist-get 'MatchedStatements result-item))
         (policy-ids (if matched-statements
                         (mapcar (lambda (stmt) (alist-get 'SourcePolicyId stmt)) matched-statements)
                       '("None")))
         (missing-context (alist-get 'MissingContextValues result-item)))
    `(:action ,(alist-get 'EvalActionName result-item)
      :decision ,decision
      :resource ,(alist-get 'EvalResourceName result-item)
      :pb-allowed ,(if pb-detail (alist-get 'AllowedByPermissionsBoundary pb-detail) nil)
      :org-allowed ,(if org-detail (alist-get 'AllowedByOrganizations org-detail) nil)
      :policy-ids-str ,(mapconcat #'identity policy-ids ", ")
      :missing-context-str ,(if missing-context (mapconcat 'identity missing-context ", ") "None")
      :decision-face ,(if (string= decision "allowed") 'success 'error))))

(defun org-aws-iam-role-insert-simulation-warning ()
  "Insert the standard simulation warning into the current buffer."
  (let ((start (point)))
    (insert "*** WARNING: Simplified Simulation ***\n")
    (insert "This test only checks the role's identity-based policies against the given actions.\n")
    (insert "- It does NOT include resource-based policies (e.g., S3 bucket policies).\n")
    (insert "- It does NOT allow providing specific context keys (e.g., source IP, MFA).\n")
    (insert "- Results ARE affected by Service Control Policies (SCPs).\n\n")
    (insert "For comprehensive testing, use the AWS Console Policy Simulator.\n")
    (insert "************************************\n\n")
    (add-face-text-property start (point) 'font-lock-warning-face)))

(provide 'org-aws-iam-role-simulate)
;;; org-aws-iam-role-simulate.el ends here
