ALTER TABLE approval_requests
ADD COLUMN replacement_approval_id TEXT REFERENCES approval_requests(id);

CREATE UNIQUE INDEX approval_replacement_unique
ON approval_requests(replacement_approval_id)
WHERE replacement_approval_id IS NOT NULL;
