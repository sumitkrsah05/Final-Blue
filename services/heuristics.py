"""Deterministic fallback analyser.

When the LLM endpoint is unconfigured, cold, or fails every retry, the run must
still produce a usable report — a demo that dies on a Modal cold start is worse
than one that degrades. This module produces the same
:class:`~models.schemas.FindingAnalysis` shape from rule-based playbooks, and
tags it ``analysis_source="heuristic"`` so nobody mistakes it for AI analysis.

It is also the reference for what a "complete" analysis looks like: the LLM path
validates against the same model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from models.schemas import (
    BusinessImpact,
    ExecutiveSummary,
    FindingAnalysis,
    MitreAttack,
    MitreTechnique,
    Recommendation,
    RedFinding,
    RedTeamReport,
    RiskAssessment,
    RootCause,
    Severity,
    TechnicalSummary,
)
from services import mitre

# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Playbook:
    """A rule-based analysis template for one class of finding."""

    name: str
    pattern: str
    root_cause: str
    categories: tuple[str, ...]
    analysis: str
    impact: dict[str, str] = field(default_factory=dict)
    recommendations: tuple[tuple[str, str, str, str], ...] = ()
    detections: tuple[str, ...] = ()


PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        name="tls_certificate",
        pattern=r"certificat|expired|self[- ]signed|hostname mismatch|ssl dns",
        root_cause="Certificate lifecycle management is manual or unmonitored",
        categories=("misconfiguration", "weak TLS configuration"),
        analysis=(
            "The service presents an X.509 certificate that clients cannot fully "
            "trust — it is expired, self-signed, or does not match the hostname "
            "being requested. Browsers and API clients respond with interstitial "
            "warnings that users are trained to click through, which destroys the "
            "signal that would otherwise reveal a genuine adversary-in-the-middle. "
            "An attacker positioned on the network path can therefore present their "
            "own certificate and expect the same click-through, intercepting "
            "session cookies and credentials in transit. The underlying cause is "
            "almost always process rather than technology: renewal is not automated "
            "and no monitor alerts before expiry."
        ),
        impact={
            "confidentiality": "Session tokens and credentials can be read by an on-path attacker whose certificate users accept as readily as the broken one.",
            "integrity": "Injected responses cannot be distinguished from legitimate ones once trust validation is habitually bypassed.",
            "compliance": "PCI DSS 4.0 requirement 4.2.1 requires strong cryptography with valid, trusted certificates for cardholder data in transit.",
        },
        recommendations=(
            ("immediate", "configuration", "Reissue and deploy a certificate from a publicly trusted CA covering every served hostname and SAN.", "Restores trust validation so client warnings become meaningful again."),
            ("short_term", "hardening", "Automate issuance and renewal with ACME (certbot, cert-manager, or the platform's managed certificate service).", "Removes the manual step that caused the lapse."),
            ("short_term", "monitoring", "Alert on certificates within 30 days of expiry across every endpoint, not just the primary domain.", "Turns a silent outage into a ticket with lead time."),
            ("long_term", "architecture", "Terminate TLS at a managed edge (load balancer or CDN) so certificate lifecycle is a platform concern, not a per-service one.", "Eliminates the class of defect rather than this instance."),
        ),
        detections=(
            "Alert when TLS certificate expiry for any monitored FQDN drops below 30 days (synthetic probe or CT log watch).",
            "Alert on unexpected certificate issuer or fingerprint changes for production hostnames, which indicates interception or misissuance.",
        ),
    ),
    Playbook(
        name="weak_crypto",
        pattern=r"weak cipher|deprecated tls|ssl ?v[23]|tls ?1\.[01]|rc4|3des|md5|sha1|poodle|beast|sweet32",
        root_cause="TLS configuration retains legacy protocol versions and cipher suites for backwards compatibility",
        categories=("weak TLS configuration", "insecure default"),
        analysis=(
            "The endpoint negotiates protocol versions or cipher suites that are no "
            "longer considered strong — typically TLS 1.0/1.1, or suites using RC4, "
            "3DES, CBC-mode constructions, or non-forward-secret key exchange. These "
            "carry published cryptographic weaknesses that reduce the work factor for "
            "recovering plaintext from captured traffic. The practical risk depends on "
            "an attacker's network position: it is not remotely exploitable on its own, "
            "but it removes a layer of defence for anyone able to observe traffic, and "
            "it is a reliable audit finding. The cause is usually an inherited default "
            "in a web server or load balancer config that was never revisited."
        ),
        impact={
            "confidentiality": "Captured traffic is substantially cheaper to decrypt than a modern suite would allow, exposing credentials and session material.",
            "compliance": "PCI DSS and most baselines mandate TLS 1.2 as a floor; legacy versions are an audit failure regardless of exploitability.",
        },
        recommendations=(
            ("immediate", "configuration", "Disable TLS 1.0/1.1 and all RC4, 3DES, EXPORT and NULL cipher suites at the terminating proxy.", "Removes the negotiable weak options in a single config change."),
            ("short_term", "hardening", "Adopt the Mozilla 'intermediate' TLS profile: TLS 1.2+ with forward-secret ECDHE suites, and enable TLS 1.3.", "Gives a maintained, vendor-neutral baseline instead of a hand-tuned list."),
            ("short_term", "configuration", "Set Strict-Transport-Security with max-age=31536000 and includeSubDomains once HTTPS is confirmed everywhere.", "Prevents protocol downgrade before the handshake occurs."),
            ("long_term", "monitoring", "Add continuous TLS posture scanning to the deployment pipeline and gate releases on the result.", "Stops configuration drift from silently reintroducing weak suites."),
        ),
        detections=(
            "Flag successful TLS handshakes negotiating versions below 1.2 in load-balancer access logs.",
            "Periodically scan public endpoints (testssl.sh / sslyze) and alert on any grade regression.",
        ),
    ),
    Playbook(
        name="missing_headers",
        pattern=r"missing.*header|x-frame-options|content[- ]security[- ]policy|\bcsp\b|hsts|clickjack|x-content-type",
        root_cause="Security response headers were never added to the application or edge configuration",
        categories=("missing security header", "insecure default", "misconfiguration"),
        analysis=(
            "The application omits one or more HTTP response headers that instruct the "
            "browser to enforce security boundaries on its behalf. Without them the "
            "browser applies only its permissive defaults: framing is allowed "
            "(enabling clickjacking), inline script is unrestricted (removing the "
            "mitigation that would blunt an XSS), MIME types may be sniffed, and "
            "HTTPS is not pinned for future visits. None of these is itself an entry "
            "point; each is a missing layer that makes some other flaw materially "
            "easier to exploit. The cause is that headers live in configuration that "
            "no single team owns."
        ),
        impact={
            "confidentiality": "Absent CSP, any injected script executes with full page privileges and can read session-scoped data.",
            "integrity": "Clickjacking lets an attacker induce authenticated state changes the user did not intend.",
            "customer_trust": "Header posture is externally observable and routinely cited in customer security questionnaires.",
        },
        recommendations=(
            ("immediate", "configuration", "Add Content-Security-Policy, X-Frame-Options: DENY (or CSP frame-ancestors 'none'), X-Content-Type-Options: nosniff and Referrer-Policy at the edge proxy.", "Applies to every route at once without touching application code."),
            ("short_term", "hardening", "Roll out CSP in Report-Only mode first, collect violations, then enforce.", "Avoids breaking legitimate functionality while still gathering the data needed to tighten the policy."),
            ("short_term", "detection", "Ingest CSP violation reports into the SIEM and alert on script-src violations.", "Turns the header into an XSS detection channel rather than only a mitigation."),
            ("long_term", "devsecops", "Assert required headers in an automated test that runs on every deploy.", "Prevents regression when the proxy config is next edited."),
        ),
        detections=(
            "Alert on a spike in CSP report-uri/report-to violations for script-src, which frequently indicates active injection.",
            "Post-deploy synthetic check asserting the required header set on representative routes.",
        ),
    ),
    Playbook(
        name="injection",
        pattern=r"sql\s*injection|sqli|cross[- ]site scripting|\bxss\b|command injection|remote code execution|\brce\b|template injection|deserializ|xxe|path traversal",
        root_cause="Untrusted input reaches an interpreter without parameterisation or contextual encoding",
        categories=("missing input validation", "software bug"),
        analysis=(
            "User-controlled input is incorporated into an interpreted context — a SQL "
            "statement, an HTML document, a shell command, a template, or a "
            "deserialisation routine — without the separation of code and data that "
            "would keep it inert. An attacker supplies input crafted so that part of it "
            "is parsed as instructions rather than as a value, and the interpreter "
            "executes it with the application's own privileges. This is the highest-"
            "leverage class of web vulnerability: depending on the sink it yields "
            "database contents, session hijacking, or direct code execution on the "
            "server, and it is directly reachable from the internet without credentials."
        ),
        impact={
            "confidentiality": "Whole tables or files readable by the application process can be extracted, typically including customer PII and credentials.",
            "integrity": "Records can be modified or deleted, and in code-execution cases persistent backdoors can be installed.",
            "availability": "Destructive queries or resource-heavy payloads can take the service down.",
            "financial": "Breach notification, forensics and regulatory penalties dominate cost; a confirmed data-theft event is materially expensive.",
            "compliance": "Directly implicates GDPR Article 32 and PCI DSS requirement 6.2; injection is the archetypal 'known and preventable' defect.",
            "remote_compromise": "Command, template and deserialisation injection give remote code execution and should be treated as a compromise until proven otherwise.",
            "lateral_movement": "Application service credentials recovered through the flaw usually open other internal systems.",
        },
        recommendations=(
            ("immediate", "compensating", "Deploy a targeted WAF rule for the affected parameter and route while the code fix is developed.", "Buys time without shipping a rushed change to a security-critical code path."),
            ("immediate", "patch", "Replace string-concatenated queries with parameterised statements or a query builder that binds values.", "Removes the ability for input to be parsed as code, which is the defect itself."),
            ("short_term", "patch", "Apply contextual output encoding for every reflected value and validate input against an allow-list of expected shape.", "Addresses the sinks the scanner did not reach as well as the one it did."),
            ("short_term", "hardening", "Reduce the database account's privileges to exactly what the application needs.", "Caps the blast radius of any injection that survives the fix."),
            ("long_term", "devsecops", "Gate merges on SAST and DAST coverage for injection classes, with the affected route in the regression suite.", "Converts a one-off fix into a durable control."),
        ),
        detections=(
            "Alert on SQL syntax errors and UNION/sleep patterns in application error logs — successful blind injection is noisy before it is successful.",
            "SIEM rule: single source IP producing many 500s across distinct parameters within a short window.",
            "Alert on outbound connections initiated by the web application process to non-allow-listed destinations, which indicates post-exploitation.",
        ),
    ),
    Playbook(
        name="default_credentials",
        pattern=r"default (credential|password|account)|weak password|admin:admin|no authentication|unauthenticated access|anonymous",
        root_cause="Software was deployed without changing shipped defaults or enabling authentication",
        categories=("insecure default", "weak authentication", "misconfiguration"),
        analysis=(
            "An interface accepts vendor-default credentials or requires no "
            "authentication at all. Default credential lists are published and are the "
            "first thing both commodity scanners and opportunistic attackers try, so "
            "exposure time is effectively exploitation time. Because the access granted "
            "is legitimate authentication rather than an exploit, it produces no "
            "crash, no anomaly, and often no distinguishable log entry — making this "
            "both trivially exploitable and hard to detect after the fact."
        ),
        impact={
            "confidentiality": "The attacker obtains whatever the account can see, frequently administrative visibility over the whole component.",
            "integrity": "Administrative access permits configuration changes and durable persistence.",
            "privilege_escalation": "Default accounts are typically privileged, so this is immediate escalation rather than a step toward it.",
            "lateral_movement": "Credentials reused across the estate turn one exposed console into estate-wide access.",
        },
        recommendations=(
            ("immediate", "configuration", "Rotate the credential now and confirm the default no longer authenticates.", "Closes an actively scanned-for entry point."),
            ("immediate", "detection", "Review authentication logs for the affected account back to its deployment date.", "Exposure of this kind must be assumed used until the logs say otherwise."),
            ("short_term", "hardening", "Require SSO/MFA on administrative interfaces and restrict them to a management network or VPN.", "Removes reliance on a single shared secret."),
            ("long_term", "preventive", "Add a deployment check that fails the pipeline when known default credentials authenticate.", "Prevents the same misstep on the next deployment."),
        ),
        detections=(
            "Alert on any successful authentication as a known default account name (admin, root, guest, test) on production systems.",
            "Alert on administrative-console logins from outside expected source ranges or outside business hours.",
        ),
    ),
    Playbook(
        name="exposed_secrets",
        pattern=r"exposed (secret|key|token)|api key|hardcoded|credentials in|\.env|\.git|backup file|private key",
        root_cause="Secrets are stored in artefacts that get published, rather than in a secret manager",
        categories=("exposed secret", "misconfiguration"),
        analysis=(
            "Credential material is reachable by an unauthenticated requester — through "
            "an exposed .env or .git directory, a backup artefact left in the web root, "
            "or a key committed into a served path. Any secret in this position must be "
            "treated as compromised: retrieval leaves an ordinary access-log entry that "
            "is indistinguishable from benign traffic, so there is no reliable way to "
            "prove it was not taken. The root cause is that secrets live in files that "
            "travel with the deployment instead of being injected at runtime."
        ),
        impact={
            "confidentiality": "The exposed credential grants whatever access it was issued for, bypassing the application's own controls entirely.",
            "privilege_escalation": "Service and deploy keys are usually broadly scoped, so recovery of one often yields more privilege than any application account.",
            "lateral_movement": "Cloud and CI credentials extend reach well beyond the exposed host.",
            "data_exposure": "Source history recovered from an exposed .git directory frequently contains additional historical secrets.",
        },
        recommendations=(
            ("immediate", "configuration", "Revoke and reissue every credential reachable through the exposure — rotation, not removal of the file, is the fix.", "The secret is already public; deleting the file does not un-disclose it."),
            ("immediate", "configuration", "Block access to dotfiles, VCS directories and backup extensions at the web server or CDN.", "Stops ongoing retrieval within minutes."),
            ("short_term", "hardening", "Move secrets into a managed secret store injected at runtime (Vault, AWS Secrets Manager, Kubernetes secrets with RBAC).", "Removes secrets from deployable artefacts entirely."),
            ("long_term", "devsecops", "Enable pre-commit and CI secret scanning, and audit history for secrets already committed.", "Prevents reintroduction and cleans up the backlog."),
        ),
        detections=(
            "Alert on any HTTP request to /.git/, /.env, *.bak, *.sql or *.zip paths — legitimate traffic never requests these.",
            "Enable cloud-provider anomaly alerting on the rotated credentials in case the old ones are used elsewhere.",
        ),
    ),
    Playbook(
        name="access_control",
        pattern=r"authoriz|access control|idor|insecure direct object|privilege escalation|forced browsing|admin (panel|interface|console)|login (page|panel)",
        root_cause="Authorisation is enforced inconsistently, or an administrative surface is exposed more broadly than intended",
        categories=("missing authorization", "poor access control", "excessive network exposure"),
        analysis=(
            "An interface or object is reachable by a principal who should not reach it. "
            "This is either a missing authorisation check (the server trusts a "
            "client-supplied identifier without verifying ownership) or an "
            "administrative surface published to a wider network than its threat model "
            "assumes. Exploitation requires no tooling — the attacker changes an "
            "identifier or visits a URL — which makes it easy to find at scale and easy "
            "to miss in testing, since the happy path always looks correct."
        ),
        impact={
            "confidentiality": "Records belonging to other tenants or users can be enumerated and read.",
            "integrity": "Where the same gap covers writes, records can be modified across tenant boundaries.",
            "compliance": "Cross-tenant data access is a reportable personal-data breach under GDPR.",
            "privilege_escalation": "Exposed administrative functions convert an ordinary user session into an administrative one.",
        },
        recommendations=(
            ("immediate", "configuration", "Restrict the administrative surface to a management network, VPN or IP allow-list.", "Shrinks the attacker population immediately while the code fix lands."),
            ("short_term", "patch", "Enforce object-level authorisation server-side on every request, deriving the subject from the session rather than the request body.", "Fixes the actual defect instead of hiding the endpoint."),
            ("short_term", "detection", "Log authorisation denials with subject and object, and alert on enumeration patterns.", "Makes exploitation attempts visible."),
            ("long_term", "architecture", "Centralise authorisation in shared middleware or a policy engine so new endpoints inherit enforcement by default.", "Removes per-endpoint discipline as the control."),
        ),
        detections=(
            "Alert when one session requests many distinct object IDs in a short window (IDOR enumeration signature).",
            "Alert on any successful access to administrative routes from non-management source ranges.",
        ),
    ),
    Playbook(
        name="outdated_component",
        pattern=r"outdated|end[- ]of[- ]life|unpatched|\bcve-|vulnerable version|known vulnerabilit|dependency",
        root_cause="Patch and dependency management does not cover this component on a defined cadence",
        categories=("missing patch", "insecure dependency"),
        analysis=(
            "The target runs a software version with publicly documented "
            "vulnerabilities. Public disclosure means both the technical detail and, "
            "usually, working exploit code are already available, so the barrier to "
            "exploitation is version identification rather than research — and the "
            "version is being advertised. Risk is a function of whether the specific "
            "vulnerable code path is reachable in this deployment, which the scanner "
            "typically cannot determine and which should be confirmed before "
            "deprioritising."
        ),
        impact={
            "confidentiality": "Depends on the specific CVE; component-level flaws often expose everything the component processes.",
            "remote_compromise": "Where a published CVE carries remote code execution, assume full host compromise is available to any attacker who finds the version.",
            "compliance": "Running components with known vulnerabilities is an explicit failure under PCI DSS 6.3 and most control frameworks.",
        },
        recommendations=(
            ("immediate", "patch", "Upgrade the component to a supported, patched release, prioritised by whether the vulnerable path is reachable.", "Directly removes the vulnerable code."),
            ("immediate", "configuration", "Where an upgrade is not immediately possible, apply the vendor's documented mitigation or disable the affected module.", "Reduces exposure during the change window."),
            ("short_term", "hardening", "Suppress version banners so that trivial fingerprinting no longer identifies targets.", "Raises attacker cost slightly; explicitly not a substitute for patching."),
            ("long_term", "devsecops", "Maintain an SBOM and gate builds on SCA findings above an agreed severity, with a defined patch SLA per severity.", "Turns patching from a reactive scramble into a measured process."),
        ),
        detections=(
            "Alert on exploit-signature traffic for the specific CVE at the WAF or IDS.",
            "Reconcile the deployed-version inventory against advisory feeds daily and raise a ticket on new matches.",
        ),
    ),
    Playbook(
        name="information_disclosure",
        pattern=r"information disclosure|verbose error|stack trace|debug|directory listing|version|banner|detect|fingerprint|disclosure",
        root_cause="Diagnostic verbosity intended for development is enabled in production",
        categories=("information disclosure", "insecure default", "misconfiguration"),
        analysis=(
            "The service volunteers information about its own implementation — product "
            "and version banners, directory indexes, stack traces, or internal paths. "
            "No single disclosure is exploitable, but together they let an attacker "
            "skip reconnaissance and go straight to the exploits that match this exact "
            "stack, and error detail in particular can reveal internal hostnames, file "
            "paths and query structure. Treat this as reducing attacker cost rather "
            "than as an entry point, and prioritise it accordingly."
        ),
        impact={
            "confidentiality": "Implementation detail leaks; in verbose-error cases this can extend to internal paths, hostnames and query fragments.",
            "operational_disruption": "Low — remediation is configuration-only and carries little regression risk.",
            "reputation": "Minor in isolation, but routinely flagged in third-party assessments and customer questionnaires.",
        },
        recommendations=(
            ("immediate", "configuration", "Disable debug mode and replace verbose error pages with a generic handler that logs detail server-side.", "Removes the highest-value part of the disclosure at no functional cost."),
            ("short_term", "hardening", "Suppress product/version banners (ServerTokens Prod, server_tokens off, expose_php off) and disable directory indexing.", "Removes the fingerprinting shortcut."),
            ("long_term", "devsecops", "Add a production configuration baseline check to the deployment pipeline.", "Stops debug settings from reaching production again."),
        ),
        detections=(
            "Alert on production responses containing stack-trace markers (Exception, Traceback, at java., ORA-).",
            "Track scanner-like request patterns: many 404s across common paths from one source.",
        ),
    ),
    Playbook(
        name="network_exposure",
        pattern=r"open port|port scan|service detect|exposed service|network service|nmap|ftp|telnet|smb|rdp|database (port|exposed)",
        root_cause="Network exposure is broader than the service's intended audience requires",
        categories=("excessive network exposure", "misconfiguration"),
        analysis=(
            "A network service is reachable from a broader network than its function "
            "requires. Every reachable port is attack surface: it can be fingerprinted, "
            "tested for default credentials, and targeted the moment a vulnerability is "
            "published for that software. Legacy management protocols are the worst "
            "case, since several transmit credentials without encryption. The cause is "
            "usually an over-permissive security group or firewall rule that was "
            "widened for troubleshooting and never narrowed again."
        ),
        impact={
            "confidentiality": "Cleartext management protocols expose credentials to anyone on the path.",
            "availability": "Directly reachable services can be targeted for resource exhaustion.",
            "lateral_movement": "Internal services reachable from untrusted networks are the usual pivot point after an initial foothold.",
        },
        recommendations=(
            ("immediate", "configuration", "Restrict the service to required source ranges via security group or host firewall.", "Cheap, reversible, and immediately shrinks the attack surface."),
            ("short_term", "hardening", "Replace cleartext protocols with encrypted equivalents (SSH for telnet/FTP) and disable what is unused.", "Removes credential interception and unnecessary surface together."),
            ("long_term", "architecture", "Segment management traffic onto a separate network and require bastion or zero-trust access.", "Makes broad exposure structurally impossible rather than policy-dependent."),
        ),
        detections=(
            "Alert on connections to management ports from outside approved ranges.",
            "Diff external port inventory daily and alert on newly opened ports.",
        ),
    ),
)

_GENERIC = Playbook(
    name="generic",
    pattern=r".*",
    root_cause="Insufficient detail in the report to determine a specific root cause",
    categories=("unknown",),
    analysis=(
        "The Red Agent recorded this finding without enough surrounding detail for a "
        "confident classification. The evidence supports treating it as a real "
        "observation about the target's configuration or exposed surface, but the "
        "specific weakness, its reachability, and its exploitability all need manual "
        "confirmation before remediation effort is committed. Validate it against the "
        "affected asset, then reclassify."
    ),
    impact={
        "confidentiality": "Undetermined — insufficient evidence in the report to assess.",
        "operational_disruption": "Triage effort only, until the finding is confirmed.",
    },
    recommendations=(
        ("immediate", "hardening", "Manually validate the finding against the affected asset and record the confirmed technical detail.", "Prevents both wasted remediation effort and a real issue being dismissed."),
        ("short_term", "configuration", "Once confirmed, apply the vendor or framework hardening guidance for the affected component.", "Standard guidance covers the majority of configuration-class findings."),
        ("long_term", "monitoring", "Add the affected asset to recurring authenticated scanning so future findings arrive with fuller context.", "Improves the evidence quality of subsequent assessments."),
    ),
    detections=(
        "Ensure the affected asset forwards application and access logs to the SIEM so future activity against it is observable.",
    ),
)

# Fields of BusinessImpact that get a neutral default when a playbook is silent.
_DEFAULT_IMPACT: dict[str, str] = {
    "confidentiality": "No direct confidentiality impact identified from the available evidence.",
    "integrity": "No direct integrity impact identified from the available evidence.",
    "availability": "No direct availability impact identified from the available evidence.",
    "financial": "Cost is dominated by remediation effort rather than by loss events, on current evidence.",
    "compliance": "Contributes to control findings in configuration-hardening scope (ISO 27001 A.8, CIS benchmarks).",
    "operational_disruption": "Remediation is expected to be low-risk and schedulable during normal change windows.",
    "reputation": "Limited in isolation; externally visible findings accumulate into a poor posture impression.",
    "customer_trust": "Material only if this finding is combined with others during a customer security review.",
    "data_exposure": "No specific dataset identified as exposed by this finding alone.",
    "privilege_escalation": "No privilege escalation path identified from this finding alone.",
    "lateral_movement": "No lateral movement path identified from this finding alone.",
    "remote_compromise": "This finding alone does not establish a remote compromise path.",
}


def _match_playbook(finding: RedFinding) -> Playbook:
    """Pick the most specific playbook whose pattern matches the finding."""
    haystack = " ".join(
        (finding.title, finding.description, finding.evidence, finding.asset)
    ).lower()
    for playbook in PLAYBOOKS:
        if re.search(playbook.pattern, haystack):
            return playbook
    return _GENERIC


def _risk_score(finding: RedFinding) -> float:
    """Blend severity, CVSS, EPSS and the Red Agent's own score into 0–10."""
    if finding.cvss is not None:
        base = min(max(finding.cvss, 0.0), 10.0)
    else:
        base = {
            Severity.CRITICAL: 9.3,
            Severity.HIGH: 7.8,
            Severity.MEDIUM: 5.4,
            Severity.LOW: 3.1,
            Severity.INFO: 1.2,
            Severity.UNKNOWN: 2.5,
        }[finding.severity]

    if finding.risk_score is not None:
        # The Red Agent reports risk on a 0-100 scale; average it in at low weight.
        base = base * 0.8 + min(finding.risk_score / 10.0, 10.0) * 0.2
    if finding.epss is not None and finding.epss >= 0.1:
        # Meaningful real-world exploitation probability nudges the score up.
        base = min(10.0, base + min(finding.epss, 1.0))
    return round(base, 1)


def _likelihood(finding: RedFinding) -> str:
    if finding.epss is not None and finding.epss >= 0.5:
        return "Very High"
    if finding.cve_ids:
        return "High"
    return {
        Severity.CRITICAL: "High",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Low",
        Severity.UNKNOWN: "Medium",
    }[finding.severity]


def _priority(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "P0",
        Severity.HIGH: "P1",
        Severity.MEDIUM: "P2",
        Severity.LOW: "P3",
        Severity.INFO: "P3",
        Severity.UNKNOWN: "P2",
    }[severity]


class HeuristicAnalyzer:
    """Rule-based analyser used when the LLM is unavailable."""

    def analyze_finding(self, finding: RedFinding, report: RedTeamReport) -> FindingAnalysis:
        """Produce a complete :class:`FindingAnalysis` without calling an LLM."""
        playbook = _match_playbook(finding)
        techniques = mitre.map_text(
            finding.title,
            finding.description,
            finding.evidence,
            asserted=finding.techniques,
        )

        impact_values = dict(_DEFAULT_IMPACT)
        impact_values.update(playbook.impact)
        narrative = (
            f"{finding.title} on {finding.asset or report.target} is rated "
            f"{finding.severity.label}. {playbook.root_cause}. Remediation is "
            f"{'urgent' if finding.severity.rank >= 4 else 'schedulable'} and the "
            f"immediate actions below are the ones that reduce exposure fastest."
        )

        score = _risk_score(finding)
        analysis_text = playbook.analysis
        if finding.description:
            analysis_text = f"{analysis_text}\n\nScanner detail: {finding.description}"

        return FindingAnalysis(
            id=finding.display_id,
            title=finding.title,
            severity=finding.severity,
            asset=finding.asset or report.target,
            analysis=analysis_text,
            root_cause=RootCause(
                primary=playbook.root_cause,
                categories=list(playbook.categories),
                explanation=(
                    f"Findings of this class ({playbook.name.replace('_', ' ')}) almost "
                    f"always originate in {playbook.root_cause.lower()}. Confirm against "
                    f"the change history for {finding.asset or report.target} before "
                    "committing remediation effort."
                ),
            ),
            business_impact=BusinessImpact(**impact_values, narrative=narrative),
            mitre_attack=MitreAttack(
                tactics=mitre.tactics_for(techniques),
                techniques=[
                    MitreTechnique(
                        id=t.id,
                        name=t.name,
                        tactic=t.tactic,
                        rationale=(
                            "Asserted by the scanner and confirmed against the technique "
                            "catalog."
                            if t.id in {mitre.normalise_id(x) for x in finding.techniques}
                            else "Inferred from the finding class by keyword mapping."
                        ),
                    )
                    for t in techniques
                ],
                notes=(
                    ""
                    if techniques
                    else "No reasonable ATT&CK mapping could be derived from the "
                    "available evidence; this finding describes a condition rather "
                    "than adversary behaviour."
                ),
            ),
            risk_assessment=RiskAssessment(
                overall_risk_score=score,
                likelihood=_likelihood(finding),
                impact=finding.severity.label,
                priority=_priority(finding.severity),
                risk_category=Severity.from_cvss(score),
                reasoning=(
                    f"Derived deterministically: severity {finding.severity.label}"
                    + (f", CVSS {finding.cvss}" if finding.cvss is not None else "")
                    + (f", EPSS {finding.epss}" if finding.epss is not None else "")
                    + (
                        f", Red Agent risk {finding.risk_score}"
                        if finding.risk_score is not None
                        else ""
                    )
                    + ". Produced by the heuristic analyser; no AI reasoning was applied."
                ),
            ),
            recommendations=[
                Recommendation(
                    horizon=horizon,
                    category=category,
                    action=action,
                    rationale=rationale,
                    effort="Medium" if horizon == "long_term" else "Low",
                )
                for horizon, category, action, rationale in playbook.recommendations
            ],
            detection_rules=list(playbook.detections),
            analysis_source="heuristic",
        )

    def executive_summary(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> ExecutiveSummary:
        """Roll analyses up into a management-facing summary."""
        ranked = sorted(
            analyses, key=lambda a: a.risk_assessment.overall_risk_score, reverse=True
        )
        serious = [a for a in ranked if a.severity.rank >= Severity.MEDIUM.rank]
        counts = report.severity_counts
        distribution = ", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings"

        if not analyses:
            posture = (
                f"The assessment of {report.target} produced no findings. That is a "
                "clean result for the scope tested, but scope and depth should be "
                "confirmed before it is read as an assurance statement."
            )
        elif serious:
            posture = (
                f"The assessment of {report.target} produced {len(analyses)} findings "
                f"({distribution}), of which {len(serious)} are medium severity or "
                f"above and warrant scheduled remediation. The pattern points to "
                f"configuration and patch management as the areas needing attention "
                f"rather than to a systemic failure of the application's security design."
            )
        else:
            posture = (
                f"The assessment of {report.target} produced {len(analyses)} findings "
                f"({distribution}), all low severity or informational. No exploitable "
                "path to compromise was demonstrated. The work here is closing "
                "hygiene gaps that reduce attacker reconnaissance value and would "
                "otherwise accumulate into audit findings."
            )

        themes: list[str] = []
        for analysis in ranked:
            for category in analysis.root_cause.categories:
                label = category.title()
                if label not in themes and label != "Unknown":
                    themes.append(label)

        return ExecutiveSummary(
            overall_posture=posture,
            top_risks=[
                f"{a.title} ({a.severity.label}, risk {a.risk_assessment.overall_risk_score}/10)"
                for a in ranked[:5]
            ],
            most_dangerous_findings=[
                f"{a.title} — {a.risk_assessment.reasoning.split('.')[0]}"
                for a in (serious or ranked)[:3]
            ],
            security_maturity=(
                "Recurring themes across the findings: "
                + (", ".join(themes[:6]) if themes else "no dominant theme")
                + ". Maturity is best improved by automating the controls that failed "
                "here (certificate renewal, header baselines, patch SLAs) rather than "
                "by remediating each finding individually."
            ),
            recommended_next_steps=[
                f"Assign an owner and a due date to each of the {len(serious)} findings "
                f"rated medium or above." if serious else
                "Confirm assessment scope and depth, then schedule the hygiene fixes below.",
                "Complete every immediate-horizon action in the finding detail within 7 days.",
                "Automate the failed controls (certificate renewal, security header baseline, patch SLA) within 30 days.",
                "Re-run the Red Agent assessment after remediation to verify closure.",
            ],
            business_narrative=(
                f"Current exposure on {report.target} is "
                + ("material and should be funded as remediation work this quarter."
                   if serious else
                   "limited; the residual work is low-cost hygiene that protects audit "
                   "and customer-review outcomes.")
            ),
        )

    def technical_summary(
        self, report: RedTeamReport, analyses: Sequence[FindingAnalysis]
    ) -> TechnicalSummary:
        """Roll analyses up into an engineer-facing summary."""
        categories: list[str] = []
        for analysis in analyses:
            for category in analysis.root_cause.categories:
                if category not in categories:
                    categories.append(category)

        infra: list[str] = []
        coding: list[str] = []
        for analysis in analyses:
            for rec in analysis.recommendations:
                if rec.category in {"configuration", "hardening"} and rec.action not in infra:
                    infra.append(rec.action)
                if rec.category == "patch" and rec.action not in coding:
                    coding.append(rec.action)

        return TechnicalSummary(
            developer_guidance=(
                f"{len(analyses)} findings on {report.target} reduce to these root-cause "
                f"classes: {', '.join(categories[:8]) or 'none identified'}. Fixing them "
                "at the level of the class — edge configuration, dependency policy, "
                "shared middleware — closes more surface per unit of effort than "
                "patching each finding where it was reported."
            ),
            infrastructure_recommendations=infra[:7]
            or ["Establish a hardened baseline configuration for the edge proxy and web servers."],
            secure_coding_guidance=coding[:7]
            or [
                "Parameterise every database query; never build SQL by string concatenation.",
                "Apply contextual output encoding at every point untrusted data reaches a response.",
                "Validate input against an allow-list of expected shape at the trust boundary.",
            ],
            devsecops_improvements=[
                "Run SAST and dependency (SCA) scanning on every pull request, failing the build above an agreed severity.",
                "Add DAST against a staging deployment on a nightly schedule.",
                "Enable pre-commit and CI secret scanning across all repositories.",
                "Codify the security header and TLS baseline as an automated post-deploy assertion.",
            ],
            architecture_improvements=[
                "Terminate TLS and enforce security headers at a shared edge so services inherit the baseline.",
                "Segment management interfaces onto a network reachable only via bastion or zero-trust proxy.",
                "Move all secrets into a managed secret store injected at runtime.",
                "Apply least privilege to service accounts, especially database credentials.",
            ],
        )


__all__ = ["HeuristicAnalyzer", "PLAYBOOKS", "Playbook"]
