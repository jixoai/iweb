## MODIFIED Requirements

### Requirement: Admin console application reachability
The system SHALL serve the same Admin console application through `admin.<base>`, `admin.app.<base>`, and `<base>/admin/app`. Admin HTML, JavaScript, CSS, fonts, and media SHALL be delivered from the celld deployed static-asset store rather than an asset payload embedded in Dispatcher JavaScript. The path-alias response MUST make the console's static-resource URLs resolve beneath `/admin/app/`.

#### Scenario: Administrator opens the system hostname
- **WHEN** an administrator requests `admin.<base>`
- **THEN** the node serves the Admin console application

#### Scenario: Administrator opens the path alias
- **WHEN** an administrator requests `<base>/admin/app`
- **THEN** the node serves the Admin console with its resource URLs rooted beneath `/admin/app/`

#### Scenario: Browser requests an immutable Admin resource
- **WHEN** the Admin console requests a built immutable JavaScript, CSS, font, or media resource
- **THEN** celld serves that resource from its deployed static-asset store with the resource's correct content type and cache semantics

## ADDED Requirements

### Requirement: Admin resource delivery avoids Dispatcher asset duplication
The system SHALL keep Admin static-resource bytes outside the Dispatcher source bundle. The final node image MUST NOT include a generated base64 Admin asset module or a build step that converts the Admin output into JavaScript source.

#### Scenario: Operator inspects the built node image inputs
- **WHEN** an operator reviews the Admin delivery inputs used for a node image build
- **THEN** Admin static resources are supplied as a native static-asset directory and no generated base64 asset module is present
