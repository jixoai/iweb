## MODIFIED Requirements

### Requirement: Admin login uses the owner key without browser persistence
The system SHALL require the administrator to enter a valid bootstrap or delegated owner key before showing authenticated administration data. The browser MUST keep that key only in tab-scoped session storage and MUST NOT place it in a URL, browser asset, or durable browser storage. The console SHALL not assume that the entered key is bootstrap and SHALL show authentication failures without echoing the key.

#### Scenario: New Admin tab opens
- **WHEN** an administrator opens the Admin console without a tab session
- **THEN** the console shows an administrator login view before protected data is fetched

#### Scenario: Administrator completes login with a delegated key
- **WHEN** the administrator supplies a valid active delegated owner key
- **THEN** the console creates an authenticated session for that browser tab and loads protected data without persisting the key outside session storage

#### Scenario: Administrator uses a banned key
- **WHEN** the administrator supplies a banned or expired delegated key
- **THEN** the console remains on the login view, displays a bounded authentication error, and does not retry protected requests indefinitely

## ADDED Requirements

### Requirement: Admin manages owner-key metadata and one-time issuance
The Admin console SHALL provide a dedicated Keys view that lists bootstrap and delegated metadata, creates a delegated key with an absolute expiration or no expiration, and bans delegated keys through an explicit confirmation. The plaintext returned by creation SHALL be visible only in the current interaction and SHALL never be written to durable storage, application data, audit records, or generated assets.

#### Scenario: Administrator creates a delegated key
- **WHEN** an authenticated administrator submits a valid label and expiration preset
- **THEN** the console calls `POST /v1/keys`, displays the returned plaintext once with a no-store warning, and renders the new metadata without retaining the plaintext after the dialog closes

#### Scenario: Administrator views bootstrap metadata
- **WHEN** the administrator opens the Keys view
- **THEN** the list includes a clearly marked bootstrap row with no secret, no hash, and no revoke action

#### Scenario: Administrator confirms a ban
- **WHEN** the administrator confirms revocation of a delegated key
- **THEN** the console calls the Kernel delete endpoint, refreshes metadata, and no longer offers that key as active; cancelling the dialog makes no request

### Requirement: Admin provides a transient deployment prompt and audit view
The Admin console SHALL provide a transient Chinese deployment prompt containing the MCP endpoint and a newly-created key only after the user explicitly requests copy. It SHALL also provide an Audit view with key and limit filters that renders Kernel audit metadata without any secret, query value, or raw authorization header.

#### Scenario: Administrator copies a deployment prompt
- **WHEN** the administrator chooses to copy the prompt for a newly-created key
- **THEN** the console constructs it in memory, writes it only to the user-selected clipboard operation, and does not place the prompt in URL state, workspace files, localStorage, or a server request

#### Scenario: Administrator filters audit events by key
- **WHEN** the administrator selects a delegated key and requests recent events
- **THEN** the console calls `GET /v1/audit` with the key identifier and bounded limit, then renders newest-first events including action, path, status, and timestamp

### Requirement: Admin does not gain implicit Kernel authority
The Admin application SHALL call the Kernel only with the owner credential supplied by the administrator. It MUST NOT embed `IWEB_API_TOKEN`, delegated secrets, node secrets, or privileged control credentials in the deployed browser assets.

#### Scenario: Browser receives Admin assets
- **WHEN** a visitor downloads the Admin console HTML, JavaScript, CSS, or media
- **THEN** the assets contain no bootstrap owner key, delegated key, or node secret
