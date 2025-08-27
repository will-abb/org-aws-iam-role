;;; tests/integration-e2e-test.el --- ERT integration test for org-aws-iam-role -*- lexical-binding: t; -*-

(require 'ert)
(require 'org-aws-iam-role)
(require 'cl-lib)

;; Ensure default-directory is sane (important for batch runs).
(setq default-directory
      (or (file-name-directory load-file-name)
          (file-name-directory buffer-file-name)
          default-directory))

;; First test: basic fetch
(ert-deftest org-aws-iam-role/get-full-basic-test ()
  "Call `org-aws-iam-role-get-full` with a test role and log result."
  (let ((test-role-name "test-iam-packageIamRole")
        (org-aws-iam-role-profile "williseed-iam-tester"))
    (message "DEBUG calling org-aws-iam-role-get-full with %S" test-role-name)
    (let ((role-obj (org-aws-iam-role-get-full test-role-name)))
      (message "DEBUG role-obj=%S" role-obj)
      (should role-obj))))

;; Second test: construct struct from role object
(ert-deftest org-aws-iam-role/construct-basic-test ()
  "Call `org-aws-iam-role-construct` on role object and check struct."
  (let ((test-role-name "test-iam-packageIamRole")
        (org-aws-iam-role-profile "williseed-iam-tester"))
    (let* ((role-obj (org-aws-iam-role-get-full test-role-name))
           (role-struct (org-aws-iam-role-construct role-obj)))
      (message "DEBUG role-struct=%S" role-struct)
      (should (org-aws-iam-role-p role-struct)))))

;; Third test: populate role buffer
(ert-deftest org-aws-iam-role/populate-buffer-basic-test ()
  "Populate a buffer with role details and check it contains expected markers."
  (let ((test-role-name "test-iam-packageIamRole")
        (org-aws-iam-role-profile "williseed-iam-tester"))
    (let* ((role-obj (org-aws-iam-role-get-full test-role-name))
           (role-struct (org-aws-iam-role-construct role-obj)))
      (with-temp-buffer
        (org-aws-iam-role-populate-role-buffer role-struct (current-buffer))
        (goto-char (point-min))
        (let ((buf-str (buffer-string)))
          (message "DEBUG buffer-start=%s"
                   (substring buf-str 0 (min 200 (length buf-str))))
          ;; Basic sanity checks
          (should (string-match-p "\\* IAM Role:" buf-str))
          (should (string-match-p ":ARN:" buf-str)))))))

(provide 'integration-e2e-test)
