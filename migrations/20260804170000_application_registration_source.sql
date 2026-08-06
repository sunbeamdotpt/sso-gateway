-- SSO-039: mark how each application was registered. `admin` rows come from
-- the ApplicationService (or system bootstrap); `dcr` rows come from RFC 7591
-- dynamic client registration and get consent-gated first-use entitlement.

ALTER TABLE applications
    ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'admin'
        CHECK (registration_source IN ('admin', 'dcr'));
