;;; ob-aws-iam.el --- Org Babel functions for `aws-iam` -*- lexical-binding: t; -*-

;; Copyright (C) 2025 William Bosch-Bello

;; Author: William Bosch-Bello <williamsbosch@gmail.com>
;; Maintainer: William Bosch-Bello <williamsbosch@gmail.com>
;; Created: August 16, 2025
;; Version: 1.1.0
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is part of org-aws-iam-role.
;; For license information, see `org-aws-iam-role.el`.

;;; Commentary:
;;
;; This library provides the Org Babel execution logic for the `aws-iam`
;; language, used by `org-aws-iam-role.el` to manage AWS IAM policies.

;;; Code:

(require 'json)
(require 'org-aws-iam-role)

(defun org-aws-iam-role--babel-cmd-for-trust-policy (role-name policy-document)
  "Return the AWS CLI command for updating a trust policy for ROLE-NAME."
  (format "aws iam update-assume-role-policy --role-name %s --policy-document %s%s"
          (shell-quote-argument role-name)
          (shell-quote-argument policy-document)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--babel-cmd-for-inline-policy (role-name policy-name policy-document)
  "Return the AWS CLI command for updating an inline policy."
  (format "aws iam put-role-policy --role-name %s --policy-name %s --policy-document %s%s"
          (shell-quote-argument role-name)
          (shell-quote-argument policy-name)
          (shell-quote-argument policy-document)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--babel-cmd-for-managed-policy (policy-arn policy-document)
  "Return the AWS CLI command for updating a managed policy."
  (unless policy-arn
    (user-error "Missing required header argument for managed policy: :arn"))
  (format "aws iam create-policy-version --policy-arn %s --policy-document %s --set-as-default%s"
          (shell-quote-argument policy-arn)
          (shell-quote-argument policy-document)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--param-true-p (val)
  "Return t if VAL is `t' or the string \"true\" or \"t\", case-insensitively."
  (when val
    (let ((val-str (downcase (format "%s" val))))
      (or (equal val-str "t")
          (equal val-str "true")))))

(defun org-aws-iam-role--babel-cmd-create-policy (policy-name policy-document)
  "Return AWS CLI command for creating a customer-managed policy."
  (format "aws iam create-policy --policy-name %s --policy-document %s%s"
          (shell-quote-argument policy-name)
          (shell-quote-argument policy-document)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--babel-cmd-delete-inline-policy (role-name policy-name)
  "Return AWS CLI command for deleting an inline policy."
  (format "aws iam delete-role-policy --role-name %s --policy-name %s%s"
          (shell-quote-argument role-name)
          (shell-quote-argument policy-name)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--babel-cmd-detach-managed-policy (role-name policy-arn)
  "Return AWS CLI command for detaching a managed policy."
  (format "aws iam detach-role-policy --role-name %s --policy-arn %s%s"
          (shell-quote-argument role-name)
          (shell-quote-argument policy-arn)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-aws-iam-role--babel-cmd-delete-policy (policy-arn)
  "Return AWS CLI command for deleting a managed policy."
  (format "aws iam delete-policy --policy-arn %s%s"
          (shell-quote-argument policy-arn)
          (org-aws-iam-role--cli-profile-arg)))

(defun org-babel-execute:aws-iam (body params)
  "Execute an aws-iam source block to manage an IAM policy in AWS."
  (when buffer-read-only
    (user-error "Buffer is read-only. Press C-c C-e to enable edits and execution"))

  (let* ((role-name (cdr (assoc :role-name params)))
         (policy-name (cdr (assoc :policy-name params)))
         (policy-arn (cdr (assoc :arn params)))
         (policy-type-str (cdr (assoc :policy-type params)))
         (policy-type (when policy-type-str (intern policy-type-str)))
         (create-p (org-aws-iam-role--param-true-p (cdr (assoc :create params))))
         (delete-p (org-aws-iam-role--param-true-p (cdr (assoc :delete params))))
         (detach-p (org-aws-iam-role--param-true-p (cdr (assoc :detach params))))
         cmd action-desc)

    (unless (and (or role-name create-p) policy-type)
      (user-error "Missing required header arguments: :role-name or :policy-type"))

    (cond
     ;; --- DELETE ACTION ---
     (delete-p
      (cond
       ((eq policy-type 'inline)
        (setq action-desc (format "Permanently delete inline policy '%s' from role '%s'" policy-name role-name))
        (setq cmd (org-aws-iam-role--babel-cmd-delete-inline-policy role-name policy-name)))
       ((eq policy-type 'customer-managed)
        (setq action-desc (format "Permanently delete managed policy '%s'? (This will fail if it's still attached to any entity)" policy-arn))
        (setq cmd (org-aws-iam-role--babel-cmd-delete-policy policy-arn)))
       (t (user-error "Deletion is only supported for 'inline' and 'customer-managed' policies."))))

     ;; --- DETACH ACTION ---
     (detach-p
      (when (eq policy-type 'inline)
        (user-error "Cannot detach an 'inline' policy. Use :delete instead."))
      (setq action-desc (format "Detach policy '%s' from role '%s'" (or policy-name policy-arn) role-name))
      (setq cmd (org-aws-iam-role--babel-cmd-detach-managed-policy role-name policy-arn)))

     ;; --- CREATE ACTION (now only for customer-managed) ---
     (create-p
      (if (eq policy-type 'customer-managed)
          (let ((json-string (json-encode (json-read-from-string body))))
            (setq action-desc (format "Create new customer managed policy '%s'" policy-name))
            (setq cmd (org-aws-iam-role--babel-cmd-create-policy policy-name json-string)))
        (user-error "The :create flag is only for 'customer-managed' policies. For inline policies, just execute the block without it.")))

     ;; --- DEFAULT: UPDATE (or Create for Inline) ACTION ---
     (t
      (let ((json-string (json-encode (json-read-from-string body))))
        (setq action-desc (format "Update %s for role '%s'"
                                  (if (eq policy-type 'trust-policy) "Trust Policy" (format "policy '%s'" policy-name))
                                  role-name))
        (setq cmd
              (cond
               ((eq policy-type 'trust-policy)
                (org-aws-iam-role--babel-cmd-for-trust-policy role-name json-string))
               ((eq policy-type 'inline)
                (org-aws-iam-role--babel-cmd-for-inline-policy role-name policy-name json-string))
               ((or (eq policy-type 'customer-managed)
                    (eq policy-type 'aws-managed)
                    (eq policy-type 'permissions-boundary))
                (org-aws-iam-role--babel-cmd-for-managed-policy policy-arn json-string))
               (t (user-error "Unsupported policy type for modification: %s" policy-type)))))))

    (if (y-or-n-p (format "%s" action-desc))
        (progn
          (message "Executing: %s" action-desc)
          (let ((result (string-trim (shell-command-to-string cmd))))
            (if (string-empty-p result)
                "Success!"
              result)))
      (user-error "Aborted by user."))))


(provide 'ob-aws-iam)
;;; ob-aws-iam.el ends here
