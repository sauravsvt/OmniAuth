CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    -- The user's public identity key (Base64 encoded Dilithium3 Public Key)
    identity_public_key TEXT NOT NULL,
    -- The user's KEM public key for encrypted responses (Base64 encoded Kyber768 Public Key)
    kem_public_key TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE rotation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    service_name TEXT NOT NULL, -- e.g., "netflix", "aws"
    encrypted_credentials TEXT NOT NULL, -- Encrypted with Server KEK
    last_rotated_at TIMESTAMP WITH TIME ZONE,
    status TEXT DEFAULT 'pending' -- pending, processing, failed, success
);
