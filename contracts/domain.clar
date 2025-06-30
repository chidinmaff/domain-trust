;; Domain Trust & Verification System

;; Error definitions
(define-constant ERR_ACCESS_DENIED (err u300))
(define-constant ERR_DOMAIN_EXISTS (err u301))
(define-constant ERR_DOMAIN_NOT_FOUND (err u302))
(define-constant ERR_SYSTEM_SUSPENDED (err u303))
(define-constant ERR_STAKE_TOO_LOW (err u304))
(define-constant ERR_WAIT_PERIOD_ACTIVE (err u305))
(define-constant ERR_LIMIT_EXCEEDED (err u306))
(define-constant ERR_TIME_CONSTRAINT (err u307))
(define-constant ERR_INVALID_DOMAIN_FORMAT (err u400))
(define-constant ERR_INVALID_CERT_DATA (err u401))
(define-constant ERR_INSUFFICIENT_PROOF (err u402))
(define-constant ERR_INVALID_RISK_SCORE (err u403))
(define-constant ERR_INVALID_TRUST_LEVEL (err u404))
(define-constant ERR_INVALID_OWNER_ADDRESS (err u405))

;; System parameters
(define-constant WAIT_PERIOD_DURATION u43200) ;; 12 hours in seconds
(define-constant MINIMUM_STAKE_REQUIRED u2000000) ;; in microSTX
(define-constant MIN_VALIDATOR_SCORE u75)
(define-constant MAX_PROOF_TEXT_SIZE u750)

;; Input sanitization functions
(define-private (sanitize-domain-name (domain_name (string-ascii 200)))
    (begin
        (asserts! (>= (len domain_name) u4) (err "Domain name too short"))
        (asserts! (<= (len domain_name) u200) (err "Domain name exceeds limit"))
        (asserts! (is-eq (index-of domain_name ".") none) (err "Forbidden character: ."))
        (asserts! (is-eq (index-of domain_name "/") none) (err "Forbidden character: /"))
        (asserts! (is-eq (index-of domain_name " ") none) (err "Forbidden character: space"))
        (ok true)))

(define-private (sanitize-certificate-data (cert_data (string-ascii 100)))
    (begin
        (asserts! (>= (len cert_data) u8) (err "Certificate data too short"))
        (asserts! (<= (len cert_data) u100) (err "Certificate data too long"))
        (asserts! (is-eq (index-of cert_data "<") none) (err "Forbidden character: <"))
        (asserts! (is-eq (index-of cert_data ">") none) (err "Forbidden character: >"))
        (ok true)))

(define-private (sanitize-threat-proof (threat_proof (string-ascii 750)))
    (begin
        (asserts! (>= (len threat_proof) u15) (err "Threat proof too brief"))
        (asserts! (<= (len threat_proof) u750) (err "Threat proof too lengthy"))
        (asserts! (is-eq (index-of threat_proof "<") none) (err "Forbidden character: <"))
        (asserts! (is-eq (index-of threat_proof ">") none) (err "Forbidden character: >"))
        (ok true)))

(define-private (validate-risk-level (risk_level uint))
    (begin
        (asserts! (>= risk_level u1) (err "Risk level below minimum"))
        (asserts! (<= risk_level u100) (err "Risk level above maximum"))
        (ok true)))

(define-private (validate-trust-rating (trust_rating uint))
    (begin
        (asserts! (>= trust_rating u1) (err "Trust rating below minimum"))
        (asserts! (<= trust_rating u10) (err "Trust rating above maximum"))
        (ok true)))

;; System management variables
(define-data-var system_administrator principal tx-sender)
(define-data-var domain_verification_cost uint u150)
(define-data-var required_threat_confirmations uint u3)
(define-data-var global_trust_threshold uint u2)
(define-data-var system_operational bool true)

;; Core data structures
(define-map verified_domain_registry
    {domain_name: (string-ascii 200)}
    {
        domain_owner: principal,
        trust_level: (string-ascii 30),
        verification_timestamp: uint,
        risk_assessment_score: uint,
        total_threat_reports: uint,
        staked_collateral: uint,
        last_verification_check: uint,
        certificate_hash: (string-ascii 100)
    })

(define-map threat_alert_database
    {domain_name: (string-ascii 200)}
    {
        alert_creator: principal,
        alert_timestamp: uint,
        threat_proof: (string-ascii 750),
        alert_status: (string-ascii 30),
        risk_level: uint,
        affected_users: uint
    })

(define-map validator_activity_log
    {validator_address: principal, tracked_domain: (string-ascii 200)}
    {
        validation_count: uint,
        last_validation_date: uint,
        credibility_score: uint,
        locked_stake: uint,
        successful_validations: uint
    })

(define-map domain_audit_records
    {domain_name: (string-ascii 200)}
    {
        audit_frequency: uint,
        last_audit_timestamp: uint,
        auditor_principal: principal,
        audit_rating: uint,
        compliance_notes: (string-ascii 100)
    })

(define-map validator_profile_data
    {validator_address: principal}
    {
        locked_stake: uint,
        completed_validations: uint,
        credibility_rating: uint,
        last_activity_timestamp: uint,
        validator_status: (string-ascii 30)
    })

;; Query functions
(define-read-only (get-domain-trust-data (domain_name (string-ascii 200)))
    (match (map-get? verified_domain_registry {domain_name: domain_name})
        domain_record (ok domain_record)
        (err ERR_DOMAIN_NOT_FOUND)))

(define-read-only (check-threat-alerts (domain_name (string-ascii 200)))
    (is-some (map-get? threat_alert_database {domain_name: domain_name})))

(define-read-only (get-validator-credibility (validator_address principal))
    (match (map-get? validator_activity_log {validator_address: validator_address, tracked_domain: ""})
        validator_record (get credibility_score validator_record)
        u0))

;; Primary operations
(define-public (register-trusted-domain 
    (domain_name (string-ascii 200))
    (certificate_hash (string-ascii 100)))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (required_stake (* MINIMUM_STAKE_REQUIRED (var-get global_trust_threshold))))
        
        ;; Input validation
        (asserts! (is-ok (sanitize-domain-name domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (is-ok (sanitize-certificate-data certificate_hash)) ERR_INVALID_CERT_DATA)
        (asserts! (is-eq tx-sender (var-get system_administrator)) ERR_ACCESS_DENIED)
        (asserts! (>= (stx-get-balance tx-sender) required_stake) ERR_STAKE_TOO_LOW)
        
        (match (map-get? verified_domain_registry {domain_name: domain_name})
            existing_domain ERR_DOMAIN_EXISTS
            (begin
                (try! (stx-transfer? required_stake tx-sender (as-contract tx-sender)))
                (map-set verified_domain_registry
                    {domain_name: domain_name}
                    {
                        domain_owner: tx-sender,
                        trust_level: "authenticated",
                        verification_timestamp: current_timestamp,
                        risk_assessment_score: u0,
                        total_threat_reports: u0,
                        staked_collateral: required_stake,
                        last_verification_check: current_timestamp,
                        certificate_hash: certificate_hash
                    })
                (ok true)))))

(define-public (submit-threat-alert 
    (domain_name (string-ascii 200)) 
    (threat_proof (string-ascii 750))
    (risk_level uint))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (validator_record (default-to 
            {validation_count: u0, last_validation_date: u0, credibility_score: u0, locked_stake: u0, successful_validations: u0}
            (map-get? validator_activity_log {validator_address: tx-sender, tracked_domain: domain_name}))))
        
        ;; Input validation
        (asserts! (is-ok (sanitize-domain-name domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (is-ok (sanitize-threat-proof threat_proof)) ERR_INSUFFICIENT_PROOF)
        (asserts! (is-ok (validate-risk-level risk_level)) ERR_INVALID_RISK_SCORE)
        (asserts! (var-get system_operational) ERR_SYSTEM_SUSPENDED)
        (asserts! (>= (get credibility_score validator_record) MIN_VALIDATOR_SCORE) ERR_STAKE_TOO_LOW)
        (asserts! (> (- current_timestamp (get last_validation_date validator_record)) WAIT_PERIOD_DURATION) ERR_WAIT_PERIOD_ACTIVE)
        
        (map-set threat_alert_database
            {domain_name: domain_name}
            {
                alert_creator: tx-sender,
                alert_timestamp: current_timestamp,
                threat_proof: threat_proof,
                alert_status: "under_review",
                risk_level: risk_level,
                affected_users: u1
            })
        
        (map-set validator_activity_log
            {validator_address: tx-sender, tracked_domain: domain_name}
            {
                validation_count: (+ (get validation_count validator_record) u1),
                last_validation_date: current_timestamp,
                credibility_score: (+ (get credibility_score validator_record) u3),
                locked_stake: (get locked_stake validator_record),
                successful_validations: (get successful_validations validator_record)
            })
        (ok true)))

(define-private (adjust-domain-risk-rating (domain_name (string-ascii 200)) (rating_adjustment int))
    (begin 
        (asserts! (is-ok (sanitize-domain-name domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (match (map-get? verified_domain_registry {domain_name: domain_name})
            domain_record 
                (begin
                    (map-set verified_domain_registry
                        {domain_name: domain_name}
                        (merge domain_record {
                            risk_assessment_score: (+ (get risk_assessment_score domain_record) 
                                (if (> rating_adjustment 0) 
                                    (to-uint rating_adjustment)
                                    u0))
                        }))
                    (ok true))
            ERR_DOMAIN_NOT_FOUND)))

(define-public (validate-threat-alert 
    (domain_name (string-ascii 200))
    (is_threat_confirmed bool))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
        (validator_profile (unwrap! (map-get? validator_profile_data {validator_address: tx-sender}) ERR_ACCESS_DENIED)))
        
        (asserts! (is-ok (sanitize-domain-name domain_name)) ERR_INVALID_DOMAIN_FORMAT)
        (asserts! (>= (get locked_stake validator_profile) MINIMUM_STAKE_REQUIRED) ERR_STAKE_TOO_LOW)
        
        (map-set validator_profile_data
            {validator_address: tx-sender}
            (merge validator_profile {
                completed_validations: (+ (get completed_validations validator_profile) u1),
                last_activity_timestamp: current_timestamp
            }))
        (if is_threat_confirmed
            (adjust-domain-risk-rating domain_name 15)
            (adjust-domain-risk-rating domain_name -3))))

(define-public (become-domain-validator (stake_amount uint))
    (let (
        (current_timestamp (unwrap-panic (get-block-info? time (- block-height u1)))))
        (asserts! (>= stake_amount MINIMUM_STAKE_REQUIRED) ERR_STAKE_TOO_LOW)
        (asserts! (>= (stx-get-balance tx-sender) stake_amount) ERR_STAKE_TOO_LOW)
        
        (map-set validator_profile_data
            {validator_address: tx-sender}
            {
                locked_stake: stake_amount,
                completed_validations: u0,
                credibility_rating: u100,
                last_activity_timestamp: current_timestamp,
                validator_status: "operational"
            })
        (unwrap! (stx-transfer? stake_amount tx-sender (as-contract tx-sender))
                 ERR_STAKE_TOO_LOW)
        (ok true)))

;; Administrative functions
(define-public (update-trust-threshold (new_trust_level uint))
    (begin
        (asserts! (is-ok (validate-trust-rating new_trust_level)) ERR_INVALID_TRUST_LEVEL)
        (asserts! (is-eq tx-sender (var-get system_administrator)) ERR_ACCESS_DENIED)
        (var-set global_trust_threshold new_trust_level)
        (ok true)))

(define-public (toggle-system-status (operational_status bool))
    (begin
        (asserts! (is-eq tx-sender (var-get system_administrator)) ERR_ACCESS_DENIED)
        (var-set system_operational operational_status)
        (ok true)))

(define-public (change_system_owner (new_administrator principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_administrator)) ERR_ACCESS_DENIED)
        (asserts! (not (is-eq new_administrator 'SP000000000000000000002Q6VF78)) ERR_INVALID_OWNER_ADDRESS)
        (var-set system_administrator new_administrator)
        (ok true)))

;; System setup
(define-public (setup-system (admin_principal principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_administrator)) ERR_ACCESS_DENIED)
        (asserts! (not (is-eq admin_principal 'SP000000000000000000002Q6VF78)) ERR_INVALID_OWNER_ADDRESS)
        (var-set system_administrator admin_principal)
        (var-set global_trust_threshold u2)
        (var-set system_operational true)
        (ok true)))