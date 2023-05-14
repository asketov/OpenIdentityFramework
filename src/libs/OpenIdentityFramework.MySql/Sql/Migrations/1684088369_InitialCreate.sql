CREATE TABLE `migrations`
(
    `id`             binary(16) NOT NULL DEFAULT (uuid_to_bin(uuid(), 1)),
    `name`           varchar(200) NOT NULL,
    `applied_at_utc` datetime     NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `clients`
(
    `id`                                                 binary(16) NOT NULL DEFAULT (uuid_to_bin(uuid(),1)),
    `client_id`                                          varchar(100) NOT NULL,
    `redirect_uris`                                      json         NOT NULL,
    `client_type`                                        varchar(50)  NOT NULL,
    `authorization_flows`                                json         NOT NULL,
    `code_challenge_methods`                             json         NOT NULL,
    `consent_required`                                   bit(1)       NOT NULL,
    `remember_consent`                                   bit(1)       NOT NULL,
    `consent_lifetime`                                   int          NOT NULL,
    `authorization_code_lifetime`                        int          NOT NULL,
    `include_user_claims_in_id_token_authorize_response` bit(1)       NOT NULL,
    `include_user_claims_in_id_token_token_response`     bit(1)       NOT NULL,
    `id_token_signing_algorithms`                        json         NOT NULL,
    `access_token_signing_algorithms`                    json         NOT NULL,
    `id_token_lifetime`                                  int          NOT NULL,
    `client_authentication_method`                       varchar(50)  NOT NULL,
    `access_token_format`                                varchar(50)  NOT NULL,
    `include_jwt_id_into_access_token`                   bit(1)       NOT NULL,
    `access_token_lifetime`                              int          NOT NULL,
    `refresh_token_absolute_lifetime`                    int          NOT NULL,
    `refresh_token_sliding_lifetime`                     int          NOT NULL,
    `refresh_token_expiration_type`                      varchar(50)  NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_clients_client_id` (`client_id`)
);

CREATE TABLE `scopes`
(
    `id`                binary(16) NOT NULL DEFAULT (uuid_to_bin(uuid(),1)),
    `protocol_name`     varchar(100) NOT NULL,
    `scope_token_type`  varchar(100) NOT NULL,
    `required`          bit(1)       NOT NULL,
    `show_in_discovery` bit(1)       NOT NULL,
    `user_claim_types`  json         NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_scopes_protocol_name` (`protocol_name`)
);

CREATE TABLE `resources`
(
    `id`            binary(16) NOT NULL DEFAULT (uuid_to_bin(uuid(),1)),
    `protocol_name` varchar(100) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_scopes_protocol_name` (`protocol_name`)
);

CREATE TABLE `client_scopes`
(
    `client_id` binary(16) NOT NULL,
    `scope_id`  binary(16) NOT NULL,
    PRIMARY KEY (`client_id`, `scope_id`),
    CONSTRAINT `fk_client_scopes_clients_id` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_client_scopes_scope_id` FOREIGN KEY (`scope_id`) REFERENCES `scopes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE `resource_scopes`
(
    `resource_id` binary(16) NOT NULL,
    `scope_id`    binary(16) NOT NULL,
    PRIMARY KEY (`resource_id`, `scope_id`),
    CONSTRAINT `fk_resource_scopes_resource_id` FOREIGN KEY (`resource_id`) REFERENCES `resources` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_resource_scopes_scope_id` FOREIGN KEY (`scope_id`) REFERENCES `scopes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);










