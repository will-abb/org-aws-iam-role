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
        ;; CRITICAL: We must wait for the asynchronous policy fetching to complete.
        (sleep-for 10)
        (goto-char (point-min))
        (let ((buf-str (buffer-string)))
          (message "DEBUG buffer-start=%s"
                   (substring buf-str 0 (min 200 (length buf-str))))
          (should (string-match-p "\\* IAM Role:" buf-str))
          (should (string-match-p "\\*\\* Permission Policies" buf-str)))))))

;; Helper function to normalize strings for a stable comparison.
(defun org-aws-iam-role-test--normalize-string (str)
  "Normalize STR by removing the unique timestamp and standardizing newlines."
  (when str
    (let ((s (replace-regexp-in-string " <[0-9-]+>" "" str)))
      (replace-regexp-in-string "\r\n" "\n" s))))

;; Fourth test: Final regression test against the golden file.
(ert-deftest org-aws-iam-role/regression-test-against-golden-file ()
  "Call the main view function and compare the created buffer against the golden file."
  (let ((test-role-name "test-iam-packageIamRole")
        (org-aws-iam-role-profile "williseed-iam-tester")
        (golden-file (expand-file-name
                      "tests/fixtures/integration-e2e-test-output.org"
                      (file-name-directory (or load-file-name buffer-file-name)))))
    (should (file-exists-p golden-file))

    ;; Call the main entry point to create the buffer.
    (org-aws-iam-role-view-details test-role-name)
    (sleep-for 10)

    (let* ((role-buffer
            (cl-find-if (lambda (buf)
                          (string-match-p
                           (concat "\\*IAM Role: " (regexp-quote test-role-name))
                           (buffer-name buf)))
                        (buffer-list)))
           (actual-content
            (when role-buffer
              (with-current-buffer role-buffer
                (prog1 (buffer-string)
                  (kill-buffer (current-buffer))))))
           (expected-content
            (with-temp-buffer
              (insert-file-contents golden-file)
              (buffer-string)))
           (normalized-actual (org-aws-iam-role-test--normalize-string actual-content))
           (normalized-expected (org-aws-iam-role-test--normalize-string expected-content)))

      (should normalized-actual) ;; Make sure we found the buffer.
      (should (string= normalized-actual normalized-expected)))))


(provide 'integration-e2e-test)
