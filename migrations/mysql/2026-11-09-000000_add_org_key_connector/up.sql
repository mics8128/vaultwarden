ALTER TABLE organizations ADD COLUMN member_decryption_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN key_connector_url TEXT;
