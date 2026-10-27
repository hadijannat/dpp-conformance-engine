"""Report explanations: what would make a step conclusive, and the remediation for a fail.

Render-only. Nothing here enters the canonical decision body, so a hint never changes a
decision digest or a replay. One table, keyed by reason code, holds one line per code. The
line is phrased as an action, so it reads as the next step of an inconclusive step and as the
remediation of a failed step. A code with no entry falls back to the text of its execution
status. ``tests/test_report_hints.py`` fails for a code that the reference generator finds and
that has no entry, so the fallback covers only codes from outside the engine.

The table names no payload value and grants nothing: an operator confirms origins and trust,
never the ICS or the IXIT (ADR 0011).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from dppce.models import (
    ExecutionMode,
    ExecutionStatus,
    RequirementResult,
    ReviewStatus,
    TestResult,
    Verdict,
)

# The text of each execution status. A step gets it when its code has no entry.
BY_STATUS: Final[dict[ExecutionStatus, str]] = {
    ExecutionStatus.COMPLETED: (
        "The check ran, but its observation does not decide the step. Remove the cause in the "
        "message and run the step again."
    ),
    ExecutionStatus.NOT_RUN: (
        "The step did not run. Select a test pack that defines its test purpose and a check that "
        "this engine registers."
    ),
    ExecutionStatus.SKIPPED: (
        "No applicable requirement needs the step, or its applicability is unknown. Answer the ICS "
        "questions that decide it."
    ),
    ExecutionStatus.BLOCKED: (
        "A precondition is missing. Supply the input, the declaration, or the authorization that the "
        "message names."
    ),
    ExecutionStatus.UNSUPPORTED: (
        "This engine cannot run the check here: an engine limit. Install the optional extra, or use a "
        "version that supports the form."
    ),
    ExecutionStatus.MANUAL_UNAVAILABLE: (
        "Supply a signed manual result for the step, signed with a performer key from the trust bundle."
    ),
    ExecutionStatus.ERROR: (
        "An engine defect stopped the step. Report it with the run log. The result says nothing about "
        "the system."
    ),
}

_NO_ANSWER = (
    "No answer: the system did not answer usefully. Make the endpoint answer, then run the step again."
)
_NO_TARGET = "Declare the URL template of the resource in the IXIT, and confirm its origin as the operator."
_PARAMS = "Correct the parameters of the check in the test purpose. The check did not run with them."
_NOT_JSON = "Serve the resource as one JSON document with a JSON media type."
_TOO_LARGE = "Engine limit: the input is larger than the limit of the engine. Supply a smaller sample."
_TOO_DEEP = "Engine limit: the body is nested too deeply to judge. Serve a flatter document."
_OUTPUT = "Choose an output path that does not exist yet. The command does not overwrite a file."
_SAMPLE = "Supply the offline sample that the test purpose names, in the data directory of the run."
_EXTRA = "Install the optional extra of the check. Without it, the engine cannot judge the step."
_NOT_CONCLUSIVE = (
    "No answer: the system gave no usable answer to a probe. Make the endpoint answer, then run again."
)
_STATUS_CODE = "Answer with the status code that the rule expects for this request."
_MEDIA_TYPE = "Serve the response with the media type that the rule expects."
_SUCCESS = "Answer the request with a success status code."
_TIMESTAMP = "Get a valid timestamp token for the report from a trusted time-stamping authority."
_TLS = "Correct the TLS file or option that the message names, and run the command again."
_TRUST = "Correct the trust bundle that the message names. Only the operator chooses the trust anchors."
_KEYS = "Correct the key file or the passphrase that the message names, and run the command again."
_REPORT_STATUS = "Not a step result: a statement of the verifier on the report status list."
_NOTHING = "None: the step passed."
_LIMIT = "Engine limit: "

HINTS: Final[dict[str, str]] = {
    # --- Asset Administration Shell -----------------------------------------------------------
    "AAS.API.BUDGET_EXHAUSTED": _LIMIT + "the probes used the request budget. Raise it or test fewer items.",
    "AAS.API.ID_MISSING": "Declare the identifier of a shell or submodel that the system serves.",
    "AAS.API.NOT_AUTHORIZED": "Supply an authorization that grants the scope of the probe, then run again.",
    "AAS.API.NOT_CONCLUSIVE": _NOT_CONCLUSIVE,
    "AAS.API.NO_TARGET": _NO_TARGET,
    "AAS.API.OK": _NOTHING,
    "AAS.API.PARAMS_INVALID": _PARAMS,
    "AAS.API.PROFILE": "Make each probed operation answer as the declared API profile requires.",
    "AAS.API.VERSION_UNSUPPORTED": _LIMIT + "this engine does not test the declared API version.",
    "AAS.DEPENDENCY_MISSING": _EXTRA,
    "AAS.DPP.ELEMENT_MISSING": "Add the missing elements to the passport metadata submodel.",
    "AAS.DPP.ID_MISMATCH": "Make the identifiers in the passport metadata submodel agree with its shell.",
    "AAS.DPP.OK": _NOTHING,
    "AAS.DPP.SUBMODEL_MISSING": "Add the passport metadata submodel to the shell.",
    "AAS.INVALID": "Correct the shell file until the wrapped validator accepts it.",
    "AAS.PARAMS.INVALID": _PARAMS,
    "AAS.SAMPLE.MISSING": _SAMPLE,
    "AAS.VALID": _NOTHING,
    "AAS.VERSION.UNSUPPORTED": _LIMIT + "this engine does not validate the declared metamodel version.",
    # --- Access control -----------------------------------------------------------------------
    "ACCESS.ENTITLEMENT.MISSING": "Serve each field that the access policy grants to the role.",
    "ACCESS.ENTITLEMENT.NO_FETCH_CHANNEL": (
        "Declare a fetch channel for the role, so that the check can see its fields."
    ),
    "ACCESS.ENTITLEMENT.REFUSED": "Give the entitled role access to the resource that the policy grants.",
    "ACCESS.LEAK.ERROR": "Remove the withheld field from the error responses of this role.",
    "ACCESS.LEAK.EXPORT": "Remove the withheld field from the export responses of this role.",
    "ACCESS.LEAK.FETCH": "Remove the withheld field from the fetch responses of this role.",
    "ACCESS.LEAK.HTML": "Remove the withheld field from the HTML pages of this role.",
    "ACCESS.LEAK.SEARCH": "Remove the withheld field from the search responses of this role.",
    "ACCESS.NO_TARGET": _NO_TARGET,
    "ACCESS.POLICY.ENFORCED": _NOTHING,
    "ACCESS.POLICY.ICS_MISMATCH": "Bind the access policy that the ICS names to the profile.",
    "ACCESS.POLICY.MISSING": "Pin a readable, valid access policy in the profile.",
    "ACCESS.POLICY.NOTHING_TO_PROBE": (
        "Declare at least one withheld field and its canary in the access policy."
    ),
    "ACCESS.POLICY.NOT_DECLARED": "Name the expected access policy in the ICS.",
    "ACCESS.POLICY.NOT_FULLY_CHECKABLE": (
        "Declare a canary for each withheld field, so that each channel can be checked."
    ),
    "ACCESS.RESPONSE.NOT_DECODABLE": "Serve the response in an encoding that the engine can decode.",
    "ACCESS.RESPONSE.NOT_JSON": _NOT_JSON,
    # --- API contract -------------------------------------------------------------------------
    "API.CONTRACT.CONTENT_TYPE": "Serve the response with a media type that the pinned contract declares.",
    "API.CONTRACT.ICS_MISMATCH": "Bind the API contract that the ICS names to the profile.",
    "API.CONTRACT.MISSING": "Pin a readable API contract in the profile.",
    "API.CONTRACT.NOT_DECLARED": "Name the expected API contract in the ICS.",
    "API.CONTRACT.NO_TARGET": _NO_TARGET,
    "API.CONTRACT.OK": _NOTHING,
    "API.CONTRACT.PATH_MISMATCH": "Make the URL template of the IXIT match a path of the pinned contract.",
    "API.CONTRACT.SCHEMA": (
        "Correct the response body at the listed paths until it matches the contract schema."
    ),
    "API.CONTRACT.STATUS": "Answer with a status code that the pinned contract declares for the operation.",
    "API.CONTRACT.UNSUPPORTED_FEATURE": _LIMIT
    + "the contract uses a form that this engine does not support.",
    "API.CONTRACT.UNSUPPORTED_VERSION": _LIMIT + "this engine does not read the version of the contract.",
    "API.RESPONSE.NOT_JSON": _NOT_JSON,
    "API.RESPONSE.TOO_DEEP": _TOO_DEEP,
    # --- Authorization of the test --------------------------------------------------------------
    "AUTHORIZE.DOCUMENT.INVALID": "Correct the authorization document that the message names.",
    "AUTHORIZE.ENDPOINT.INVALID": "Give each endpoint of the authorization as a valid origin.",
    "AUTHORIZE.OUTPUT.EXISTS": _OUTPUT,
    "AUTHORIZE.PERIOD.INVALID": "Give a validity period whose start is before its end.",
    "AUTHZ.EXPIRED": "Get a new authorization of the system owner whose period covers the evaluation time.",
    "AUTHZ.ISSUER.KEY_NOT_VALID": "Sign the authorization with a key that is valid and not revoked.",
    "AUTHZ.ISSUER.MISMATCH": "Sign the authorization with a key of the issuer that it names.",
    "AUTHZ.ISSUER.UNTRUSTED": (
        "Sign the authorization with a key that the trust bundle trusts to authorize tests."
    ),
    "AUTHZ.MALFORMED": "Supply the authorization as a canonical, signed document.",
    "AUTHZ.SIGNATURE.INVALID": "Supply an authorization whose signature verifies with the trusted key.",
    "AUTHZ.SUT.MISMATCH": "Supply an authorization for this system under test.",
    # --- Data carrier ---------------------------------------------------------------------------
    "CARRIER.QR.DEPENDENCY_MISSING": _EXTRA,
    "CARRIER.QR.NOT_DECODED": "Supply a QR image with one symbol that a decoder can read.",
    "CARRIER.QR.OK": _NOTHING,
    "CARRIER.SAMPLE.MISSING": _SAMPLE,
    "CARRIER.SAMPLE.TOO_LARGE": _TOO_LARGE,
    "CARRIER.SAMPLE.UNREADABLE": "Supply the carrier sample as an image file that the engine can read.",
    # --- Data -----------------------------------------------------------------------------------
    "DATA.COMPLETENESS.MISSING": "Add the fields that the rule requires to the passport data.",
    "DATA.CONTEXT.MISSING": "Add the JSON-LD context that the rule requires to the document.",
    "DATA.CONTEXT.NOT_ALLOWED": "Use only the JSON-LD contexts on the allowlist of the test purpose.",
    "DATA.CONTEXT.NO_ALLOWLIST": "Declare the allowlist of contexts in the test purpose.",
    "DATA.CONTEXT.OK": _NOTHING,
    "DATA.FRESHNESS.STALE": "Update the passport data, so that its update time is within the allowed age.",
    "DATA.NO_TARGET": _NO_TARGET,
    "DATA.RANGE.VIOLATED": "Correct the value of the field that the message names, so that it is in range.",
    "DATA.RELATIONSHIP.VIOLATED": "Correct the related fields that the message names, so that they agree.",
    "DATA.RESPONSE.NOT_CONCLUSIVE": _NOT_CONCLUSIVE,
    "DATA.RESPONSE.NOT_JSON": _NOT_JSON,
    "DATA.RESPONSE.STATUS": _SUCCESS,
    "DATA.RESPONSE.TOO_DEEP": _TOO_DEEP,
    "DATA.RULES.APPLICABILITY_UNKNOWN": "Answer the ICS questions that decide whether the data rules apply.",
    "DATA.RULES.MISSING": "Pin the data rules that the test purpose names.",
    "DATA.RULES.NONE_APPLIED": "Answer the ICS questions, so that at least one data rule applies.",
    "DATA.RULES.OK": _NOTHING,
    "DATA.SCHEMA.DIALECT": _LIMIT + "the schema uses a dialect that this engine does not support.",
    "DATA.SCHEMA.INVALID": "Correct the document at the listed paths until it matches the pinned schema.",
    "DATA.SCHEMA.MALFORMED": "Pin a schema that is itself valid.",
    "DATA.SCHEMA.MISSING": "Pin the schema that the test purpose names.",
    "DATA.SCHEMA.NOT_LOCAL": "Pin a schema whose references resolve inside the data directory.",
    "DATA.SCHEMA.OK": _NOTHING,
    "DATA.SCHEMA.UNSUPPORTED_FORMAT": _LIMIT + "the schema uses a format that this engine does not check.",
    "DATA.UNIT.INVALID": "Give the value with a unit that the rule accepts.",
    # --- Overall verdict, used by the CI formats --------------------------------------------------
    "DECISION.OVERALL.ERROR": BY_STATUS[ExecutionStatus.ERROR],
    "DECISION.OVERALL.FAIL": "Fix the failed requirements that the report lists, then run the tests again.",
    "DECISION.OVERALL.INCONCLUSIVE": (
        "The run is not conclusive. Read the reason in the message and remove its cause."
    ),
    "DECISION.OVERALL.NOT_APPLICABLE": "No requirement applies to this scope. Check the ICS answers.",
    # --- Engine, envelope, and issuer ---------------------------------------------------------
    "ENGINE.CHECK_EXCEPTION": BY_STATUS[ExecutionStatus.ERROR],
    "ENVELOPE.BODY.INVALID": "Supply the report body unchanged, as the engine wrote it.",
    "ISSUER.ACCREDITATION.NO_REFERENCE": (
        "Give the accreditation reference with the declared accreditation status."
    ),
    "ISSUER.STATEMENT.MISMATCH": (
        "Make the issuer statement of the report agree with the issuer of the signing key."
    ),
    "ISSUER.STATEMENT.UNSPECIFIED": "Declare the issuer of the report in the run configuration.",
    # --- Identifier -----------------------------------------------------------------------------
    "IDENTIFIER.BINDING.MISMATCH": (
        "Make the identifier in the passport agree with the identifier on the carrier."
    ),
    "IDENTIFIER.BINDING.NOT_COMPARABLE": "Supply both identifiers in a form that the engine can compare.",
    "IDENTIFIER.CONSISTENT": _NOTHING,
    "IDENTIFIER.CROSS.MISMATCH": "Make the identifiers of the named sources agree.",
    "IDENTIFIER.CROSS.SOURCE_MISSING": "Supply the identifier source that the test purpose names.",
    "IDENTIFIER.EQUIVALENCE.DIFFERENT": "Make the listed parts of the two identifiers agree.",
    "IDENTIFIER.EQUIVALENCE.NOT_PARSED": "Supply identifiers that parse in their declared scheme.",
    "IDENTIFIER.EQUIVALENCE.OK": _NOTHING,
    "IDENTIFIER.GRANULARITY.KEY_UNSUPPORTED": _LIMIT + "this engine does not classify the level of this key.",
    "IDENTIFIER.GRANULARITY.MISMATCH": "Encode the identifier at the granularity that the ICS declares.",
    "IDENTIFIER.GRANULARITY.NOT_DECLARED": "Declare the granularity of the identifier in the ICS.",
    "IDENTIFIER.GRANULARITY.NOT_PARSED": "Supply an identifier that parses in its declared scheme.",
    "IDENTIFIER.GRANULARITY.OK": _NOTHING,
    "IDENTIFIER.MISMATCH": "Make the identifier in the passport agree with the identifier on the carrier.",
    "IDENTIFIER.NOT_RESOLVABLE": "Use an identifier form that resolves to the passport.",
    "IDENTIFIER.NOT_RESOLVED": "Make the identifier resolve, so that the check can compare the passport.",
    "IDENTIFIER.NO_TARGET": _NO_TARGET,
    "IDENTIFIER.PARAMS.INVALID": _PARAMS,
    "IDENTIFIER.RESOLUTION.STATUS": "Answer the resolution request with a success or a redirect status code.",
    "IDENTIFIER.RESOLVED": _NOTHING,
    "IDENTIFIER.RESOLVED.MEDIA_TYPE": _NOTHING,
    "IDENTIFIER.RESPONSE.LINKSET": "Serve a linkset that the engine can read for the identifier.",
    "IDENTIFIER.RESPONSE.MEDIA_TYPE": _MEDIA_TYPE,
    "IDENTIFIER.RESPONSE.NOT_JSON": _NOT_JSON,
    "IDENTIFIER.SCHEME.NOT_HTTPS": "Encode the identifier as an HTTPS URI.",
    "IDENTIFIER.SCHEME.UNKNOWN": "Declare an identifier scheme that this engine knows.",
    "IDENTIFIER.SCHEME.UNSUPPORTED": _LIMIT + "this engine does not check this identifier scheme.",
    "IDENTIFIER.SYNTAX.COMPRESSED": _LIMIT
    + "this engine does not decompress the identifier. Supply it plain.",
    "IDENTIFIER.SYNTAX.INVALID": "Correct the identifier syntax that the message names.",
    "IDENTIFIER.SYNTAX.OK": _NOTHING,
    "IDENTIFIER.UNRESOLVED": "Make the identifier resolve to the passport.",
    # --- Decentralized identifier -------------------------------------------------------------
    "IDENTITY.DID.ASSERTION_UNRESOLVED": (
        "List the assertion method in the DID document, so that it resolves."
    ),
    "IDENTITY.DID.ID_MISMATCH": "Make the id of the DID document equal the DID that it serves.",
    "IDENTITY.DID.KEY_FORMAT": "Publish each verification key in a format that the rule accepts.",
    "IDENTITY.DID.NOT_JSON": _NOT_JSON,
    "IDENTITY.DID.OK": _NOTHING,
    "IDENTITY.DID.PARAMS_INVALID": _PARAMS,
    "IDENTITY.DID.PRIVATE_KEY": "Remove the private key material from the DID document.",
    "IDENTITY.DID.REDIRECTED": "Serve the DID document at its own URL, without a redirect.",
    "IDENTITY.DID.SAMPLE_MISSING": _SAMPLE,
    "IDENTITY.DID.STATUS": _SUCCESS,
    "IDENTITY.DID.TOO_LARGE": _TOO_LARGE,
    "IDENTITY.DID.VERIFICATION_METHOD": "Correct the verification method that the message names.",
    # --- Integrity: certificates and signed tokens ---------------------------------------------
    "INTEGRITY.CERT.EXPIRED": "Sign with a certificate that is valid at the evaluation time.",
    "INTEGRITY.CERT.KEY_USAGE": "Sign with a certificate whose key usage permits signatures.",
    "INTEGRITY.CERT.REVOKED": "Sign with a certificate that is not revoked.",
    "INTEGRITY.FORMAT.UNSUPPORTED": _LIMIT + "this engine does not verify this signature format.",
    "INTEGRITY.ISSUER.UNTRUSTED": (
        "Sign with a certificate that chains to a trust anchor that the operator confirms."
    ),
    "INTEGRITY.JOSE.ALGORITHM": "Sign with an algorithm on the allowlist that fits the key type.",
    "INTEGRITY.JOSE.CLAIMS": "Correct the claims of the token that the message names.",
    "INTEGRITY.JOSE.EXPIRED": "Issue a credential that is valid at the evaluation time.",
    "INTEGRITY.JOSE.HEADER": "Use only the header members that the profile defines.",
    "INTEGRITY.JOSE.ISSUER_MISMATCH": "Make the issuer claim equal the issuer of the credential.",
    "INTEGRITY.JOSE.ISSUER_UNTRUSTED": (
        "Sign with a key of an issuer that the operator confirms in the trust bundle."
    ),
    "INTEGRITY.JOSE.KEY_NOT_VALID": "Sign with a key that is valid and not revoked at the evaluation time.",
    "INTEGRITY.JOSE.MALFORMED": "Serve the token as a well-formed JWS.",
    "INTEGRITY.JOSE.NOT_AVAILABLE": "Make the signed token available at the declared location.",
    "INTEGRITY.JOSE.NOT_YET_VALID": "Issue a credential that is already valid at the evaluation time.",
    "INTEGRITY.JOSE.OK": _NOTHING,
    "INTEGRITY.JOSE.PARAMS": _PARAMS,
    "INTEGRITY.JOSE.SAMPLE_MISSING": _SAMPLE,
    "INTEGRITY.JOSE.SIGNATURE": "Sign the token again, so that the signature verifies with the key.",
    "INTEGRITY.JOSE.TOO_LARGE": _TOO_LARGE,
    "INTEGRITY.JOSE.TYPE": "Set the token type that the profile requires.",
    "INTEGRITY.JOSE.UNSUPPORTED": _LIMIT + "a well-formed token in a form that this engine does not verify.",
    "INTEGRITY.KEY.UNSUPPORTED": _LIMIT + "this engine does not verify this key type.",
    "INTEGRITY.NO_TARGET": _NO_TARGET,
    "INTEGRITY.OK": _NOTHING,
    "INTEGRITY.PATH.UNSUPPORTED_CONSTRAINT": (
        _LIMIT + "the certificate path has a constraint that this engine does not check."
    ),
    "INTEGRITY.PAYLOAD.MISMATCH": "Sign the payload that the system serves, so that both agree.",
    "INTEGRITY.PAYLOAD.NOT_COMPARABLE": (
        "Serve the signed and the served payload in a form that the engine can compare."
    ),
    "INTEGRITY.SIGNATURE.INVALID": "Sign the payload again, so that the signature verifies.",
    # --- Integrity: status lists ----------------------------------------------------------------
    "INTEGRITY.STATUS.ENTRY_MALFORMED": "Correct the status entry of the credential.",
    "INTEGRITY.STATUS.ENTRY_MISSING": "Add a status entry of the tested purpose to the credential.",
    "INTEGRITY.STATUS.ENTRY_TYPE": _LIMIT + "this engine does not check this type of status entry.",
    "INTEGRITY.STATUS.INDEX_RANGE": "Give a status list index inside the status list.",
    "INTEGRITY.STATUS.LIST_FORMAT": _LIMIT + "the status list has a format that this engine does not read.",
    "INTEGRITY.STATUS.LIST_LENGTH": "Publish a status list with at least the minimum number of entries.",
    "INTEGRITY.STATUS.LIST_MALFORMED": "Publish the status list as a well-formed, encoded bitstring.",
    "INTEGRITY.STATUS.LIST_NOT_AVAILABLE": "Publish the status list at the URL that the entry names.",
    "INTEGRITY.STATUS.LIST_SIGNATURE": "Sign the status list, so that its signature verifies.",
    "INTEGRITY.STATUS.LIST_UNBOUND": "Make the signed id of the status list equal its URL.",
    "INTEGRITY.STATUS.LIST_UNTRUSTED": "Sign the status list with a key of the issuer of the credential.",
    "INTEGRITY.STATUS.LIST_VALIDITY": "Publish a status list that is valid at the evaluation time.",
    "INTEGRITY.STATUS.MISSING": "Give the credential a status entry, or declare that it has none.",
    "INTEGRITY.STATUS.OK": _NOTHING,
    "INTEGRITY.STATUS.PARAMS": _PARAMS,
    "INTEGRITY.STATUS.PURPOSE": "Publish a status list that serves the purpose of the entry.",
    "INTEGRITY.STATUS.REVOKED": (
        "The credential is revoked. Issue a new credential if the data are still valid."
    ),
    "INTEGRITY.STATUS.SAMPLE_MISSING": _SAMPLE,
    "INTEGRITY.STATUS.SIZE_UNSUPPORTED": _LIMIT + "this engine does not read status entries of this size.",
    "INTEGRITY.STATUS.STALE": "Publish a status list that is newer than its allowed age.",
    "INTEGRITY.STATUS.SUSPENDED": (
        "The credential is suspended. Lift the suspension if the data are still valid."
    ),
    "INTEGRITY.STATUS.TOO_LARGE": _TOO_LARGE,
    "INTEGRITY.TOKEN.MALFORMED": "Serve the signed token in a well-formed serialization.",
    "INTEGRITY.TOKEN.NOT_AVAILABLE": "Make the signed token available at the declared location.",
    "INTEGRITY.TOKEN.NOT_PROCESSABLE": "Serve a signed token that the engine can process.",
    "INTEGRITY.TOKEN.NO_ANSWER": _NO_ANSWER,
    "INTEGRITY.TOKEN.TOO_LARGE": _TOO_LARGE,
    "INTEGRITY.TRUST.ANCHOR_INVALID": (
        "Correct the trust anchor that the operator confirms in the trust bundle."
    ),
    "INTEGRITY.TRUST.MISSING": "Supply a trust bundle that the operator confirms.",
    # --- Report keys ----------------------------------------------------------------------------
    "KEYS.DATA_KEY.UNAVAILABLE": _KEYS,
    "KEYS.FILE.EXISTS": _OUTPUT,
    "KEYS.KEY.NOT_P256": "Use a P-256 key, the only report key type of this engine.",
    "KEYS.KEY.UNENCRYPTED": "Store the private key encrypted with a passphrase.",
    "KEYS.KEY.UNREADABLE": _KEYS,
    "KEYS.PASSPHRASE.LENGTH": "Use a passphrase of at least the length that the message names.",
    "KEYS.PASSPHRASE.MISSING": "Give the reference to the passphrase of the key.",
    # --- Manual steps ---------------------------------------------------------------------------
    "MANUAL.DIGEST.NOT_MANUAL": "Ask for the digest of a manual test purpose only.",
    "MANUAL.DIGEST.PURPOSE_AMBIGUOUS": "Name the test pack of the test purpose, so that one purpose matches.",
    "MANUAL.DIGEST.PURPOSE_UNKNOWN": "Name a test purpose of a selected test pack.",
    "MANUAL.EVIDENCE.MISMATCH": ("Supply the evidence files that the signed manual result names, unchanged."),
    "MANUAL.KEY.NOT_VALID": "Sign the manual result with a key that is valid and not revoked.",
    "MANUAL.KEY.UNTRUSTED": (
        "Sign the manual result with a key that the trust bundle names for manual results."
    ),
    "MANUAL.PURPOSE.DIGEST_MISMATCH": (
        "Sign a new manual result for the current version of the test purpose."
    ),
    "MANUAL.PURPOSE.MISMATCH": "Sign a manual result for this test purpose.",
    "MANUAL.RESULT.MALFORMED": "Supply the signed manual result as one compact JWS.",
    "MANUAL.RESULT.MISSING": "Supply a signed manual result for the step.",
    "MANUAL.RESULT.TOO_LARGE": "Supply a signed manual result that is smaller than the limit.",
    "MANUAL.REVIEW.FAILED": "Correct the finding that the reviewer recorded, then repeat the manual review.",
    "MANUAL.REVIEW.OK": _NOTHING,
    "MANUAL.SIGNATURE.INVALID": (
        "Sign the manual result again with an allowed algorithm and the trusted key."
    ),
    "MANUAL.SUT.MISMATCH": "Sign a manual result for this system under test.",
    "MANUAL.SUT.VERSION_MISMATCH": "Sign a manual result for the system version that the ICS declares.",
    "MANUAL.TIME.AFTER_EVALUATION": "Sign a manual result of a review before the evaluation time.",
    "MANUAL.TIME.OUTSIDE_KEY_VALIDITY": (
        "Sign the manual result with a key that is valid at the time of review."
    ),
    "MANUAL.TRUST.MISSING": "Supply a trust bundle that names the key of the performer.",
    # --- Mode, plan, and results ----------------------------------------------------------------
    "MODE.ILLUSTRATIVE_NOT_REVIEWABLE": "Run an illustrative rule in illustrative mode. It makes no claim.",
    "MODE.NOT_APPROVED": (
        "A reviewer must approve the interpretation (open question OQ-002). Until then, use exploratory mode."
    ),
    "MODE.NOT_ILLUSTRATIVE": "Run the requirement in exploratory or reviewed mode.",
    "MODE.NOT_PERMITTED": "Run the step in a mode that its test purpose permits.",
    "PATH.APPLICABILITY_UNKNOWN": (
        "Answer the ICS questions that decide whether the assessment path applies."
    ),
    "PATH.NO_STEP": "Add at least one test purpose to the assessment path.",
    "PLAN.BLOCKED": ("Supply a signed authorization of the system owner that grants the scope of the step."),
    "PLAN.MANUAL_UNAVAILABLE": BY_STATUS[ExecutionStatus.MANUAL_UNAVAILABLE],
    "PLAN.NOT_RUN": BY_STATUS[ExecutionStatus.NOT_RUN],
    "PLAN.SKIPPED": BY_STATUS[ExecutionStatus.SKIPPED],
    "PLAN.STEP_MISSING": "Select a test pack that defines the test purpose of the assessment path.",
    "PLAN.UNSUPPORTED": BY_STATUS[ExecutionStatus.UNSUPPORTED],
    "PROFILE.NOT_SELECTED": "Select a profile for which the test purpose is defined.",
    "RESULT.MISSING": "Run the planned step, so that the report holds its result.",
    "RESULT.NOT_PLANNED": "Use only results from the plan of this run.",
    "STATUS.SUPERSEDED": "Select the requirement that supersedes this one.",
    "STATUS.SUPERSEDED_BY_SELECTED": (
        "None: a selected requirement supersedes this one and is assessed instead."
    ),
    "STATUS.WITHDRAWN": "None: the requirement is withdrawn and is not assessed.",
    "STEP.NOT_APPLICABLE": "None: the step does not apply to the declared system.",
    # --- Content negotiation --------------------------------------------------------------------
    "NEGOTIATION.BODY": "Serve the representation that the Accept value of the request asks for.",
    "NEGOTIATION.MEDIA_TYPE": _MEDIA_TYPE,
    "NEGOTIATION.NO_TARGET": "Supply the carrier URL, so that the check can send its requests.",
    "NEGOTIATION.OK": _NOTHING,
    "NEGOTIATION.QUALITY": (
        "Follow the quality values of the Accept header when you choose a representation."
    ),
    "NEGOTIATION.STATUS": _STATUS_CODE,
    "NEGOTIATION.UNSUPPORTED": (
        "Answer an unsupported Accept value with the status code that the rule expects."
    ),
    "NEGOTIATION.VARY.MISSING": "Send a Vary header that names Accept with each negotiated response.",
    # --- Opening, proofs, and signing commands --------------------------------------------------
    "OPEN.OUTPUT.EXISTS": _OUTPUT,
    "OPEN.RECORD.NOT_IN_REPORT": (
        "Open a record that the report commits to, from the recording of the same run."
    ),
    "OPEN.RECORD.UNKNOWN": "Name a record identifier of the recording.",
    "OPENING.COMMITMENT.MISMATCH": "Supply the opening unchanged, as the engine wrote it.",
    "OPENING.FILE.MALFORMED": "Supply the opening file unchanged, as the engine wrote it.",
    "OPENING.FILE.TOO_LARGE": "Supply the opening file unchanged. It is larger than the limit.",
    "OPENING.RECORD.OK": "None: the opening matches the commitment.",
    "PROOF.FILE.MALFORMED": "Supply the proof file unchanged, as the engine wrote it.",
    "PROOF.FILE.TOO_LARGE": "Supply the proof file unchanged. It is larger than the limit.",
    "PROOF.LEAF.OK": "None: the proof leads to the root of the report.",
    "PROOF.PATH.INVALID": "Supply the proof for this report, unchanged.",
    "PROOF.REPORT.MISMATCH": "Check the proof against the report that it was made for.",
    "PROVE.OUTPUT.EXISTS": _OUTPUT,
    "PROVE.RESULT.UNKNOWN": "Name a result key that the report holds.",
    "SIGN.INPUT.LINK": "Give the input as a regular file, not as a link.",
    "SIGN.OPTION.INVALID": "Correct the option that the message names.",
    "SIGN.OUTPUT.EXISTS": _OUTPUT,
    "SIGN.OUTPUT.IS_INPUT": "Choose an output path that differs from the input path.",
    "SIGNATURE.ISSUER.NONE": "Sign the report with a key of its issuer.",
    "SIGNER.ISSUER.MISMATCH": "Sign with a key of the issuer that the attestation names.",
    "SIGNER.KEY.NOT_TRUSTED": "Sign with a key that is valid and not revoked at the signing time.",
    "SIGNER.KEY.UNKNOWN": "Sign with a key that the trust bundle names.",
    "SIGNER.LIFECYCLE.CONFLICT": "Remove the conflicting attestations of one signer from the report.",
    "SIGNER.ROLE.NOT_GRANTED": "Sign with a key that the trust bundle grants the declared role.",
    "SIGNER.ROLE.OK": "None: the trust bundle grants the declared role.",
    "SIGNER.SIGNATURE.INVALID": "Supply the signature unchanged, so that it verifies.",
    # --- Persistence and registry ---------------------------------------------------------------
    "PERSISTENCE.DIGEST.NOT_COMPARABLE": "Serve the versions in a form that the engine can compare.",
    "PERSISTENCE.NO_TARGET": _NO_TARGET,
    "PERSISTENCE.OK": _NOTHING,
    "PERSISTENCE.PARAMS.INVALID": _PARAMS,
    "PERSISTENCE.RESPONSE.NOT_CONCLUSIVE": _NOT_CONCLUSIVE,
    "PERSISTENCE.RESPONSE.NOT_JSON": _NOT_JSON,
    "PERSISTENCE.RESPONSE.STATUS": _SUCCESS,
    "PERSISTENCE.UNDECLARED_CHANGE": "Record each change of the passport as a new, declared version.",
    "REGISTRY.FIELD.MISSING": "Add the listed fields to the registry record.",
    "REGISTRY.INCONSISTENT": "Make the listed fields of the registry record agree with the passport.",
    "REGISTRY.LOOKUP.NOT_CONCLUSIVE": (
        "No answer: the registry lookup gave no usable answer. Make it answer, then run again."
    ),
    "REGISTRY.NO_TARGET": _NO_TARGET,
    "REGISTRY.OK": _NOTHING,
    "REGISTRY.PARAMS.INVALID": _PARAMS,
    "REGISTRY.RESPONSE.NOT_CONCLUSIVE": _NOT_CONCLUSIVE,
    "REGISTRY.RESPONSE.NOT_JSON": _NOT_JSON,
    "REGISTRY.RESPONSE.STATUS": _SUCCESS,
    # --- Replay ---------------------------------------------------------------------------------
    "REPLAY.DATA_ROOT.MISSING": "Give the data directory of the recorded run.",
    "REPLAY.INPUT.CHANGED": "Replay with the inputs of the recorded run, unchanged.",
    "REPLAY.INPUT.NOT_RECORDED": "Replay a recording that holds each input of the run.",
    "REPLAY.RECORDING_MISMATCH": (
        "Replay with the inputs of the recorded run. A changed input sends other requests."
    ),
    # --- Resolver -------------------------------------------------------------------------------
    "RESOLVER.CONFORMANCE.INVALID_ACCEPTED": "Reject an invalid identifier instead of resolving it.",
    "RESOLVER.CONFORMANCE.INVALID_STATUS": (
        "Answer an invalid identifier with the status code that the rule expects."
    ),
    "RESOLVER.CONFORMANCE.LINKSET_REDIRECTED": "Serve the linkset at its own URL, without a redirect.",
    "RESOLVER.CONFORMANCE.LINKSET_STATUS": _SUCCESS,
    "RESOLVER.CONFORMANCE.NO_REDIRECT": "Redirect a resolution request to the default link.",
    "RESOLVER.CONFORMANCE.OK": _NOTHING,
    "RESOLVER.LINKSET.ANCHOR": "Set the anchor of the linkset to the resolved identifier.",
    "RESOLVER.LINKSET.MEDIA_TYPE": _MEDIA_TYPE,
    "RESOLVER.LINKSET.OK": _NOTHING,
    "RESOLVER.LINKSET.RELATION_MISSING": "Add the link relations that the rule requires to the linkset.",
    "RESOLVER.LINKSET.STATUS": _SUCCESS,
    "RESOLVER.LINKSET.STRUCTURE": "Serve the linkset in the structure that the rule requires.",
    "RESOLVER.NO_TARGET": _NO_TARGET,
    "RESOLVER.PARAMS.INVALID": _PARAMS,
    "RESOLVER.WELLKNOWN.MEDIA_TYPE": _MEDIA_TYPE,
    "RESOLVER.WELLKNOWN.NOT_JSON": _NOT_JSON,
    "RESOLVER.WELLKNOWN.OK": _NOTHING,
    "RESOLVER.WELLKNOWN.REDIRECTED": (
        "Serve the resolver description at its well-known URL, without a redirect."
    ),
    "RESOLVER.WELLKNOWN.ROOT": (
        "Serve the resolver description with the root members that the rule requires."
    ),
    "RESOLVER.WELLKNOWN.STATUS": _SUCCESS,
    # --- Report status lists --------------------------------------------------------------------
    "STATUSLIST.FILE.MALFORMED": "Supply the status list file unchanged, as the issuer signed it.",
    "STATUSLIST.FILE.MISSING": "Give the status list file that the report names.",
    "STATUSLIST.FILE.OPTION": "Correct the status list option that the message names.",
    "STATUSLIST.FILE.TOO_LARGE": "Supply a status list file that is smaller than the limit.",
    "STATUSLIST.ID.MISMATCH": "Supply the status list that the report names.",
    "STATUSLIST.INDEX.OUT_OF_RANGE": "Give a status index inside the status list.",
    "STATUSLIST.ISSUER.MISMATCH": "Sign the status list with a key of the report issuer.",
    "STATUSLIST.KEY.NOT_TRUSTED": "Sign the status list with a key that is valid and not revoked.",
    "STATUSLIST.KEY.PURPOSE": "Sign the status list with a key that has the purpose status.",
    "STATUSLIST.KEY.UNKNOWN": "Sign the status list with a key that the trust bundle names.",
    "STATUSLIST.REFERENCE.NONE": _REPORT_STATUS,
    "STATUSLIST.REPORT.ACTIVE": _REPORT_STATUS,
    "STATUSLIST.REPORT.REVOKED": _REPORT_STATUS,
    "STATUSLIST.REPORT.SUSPENDED": _REPORT_STATUS,
    "STATUSLIST.REPORT.UNSIGNED": _REPORT_STATUS,
    "STATUSLIST.SIGNATURE.INVALID": "Supply the status list unchanged, so that its signature verifies.",
    "STATUSLIST.TIME.STALE": ("Supply a status list that is newer than the maximum age of the trust bundle."),
    # --- Timestamps -----------------------------------------------------------------------------
    **dict.fromkeys(
        (
            "TIMESTAMP.CMS.SIGNATURE_INVALID",
            "TIMESTAMP.CMS.SIGNING_CERT",
            "TIMESTAMP.EVIDENCE.TOO_MANY",
            "TIMESTAMP.IMPRINT.ALGORITHM",
            "TIMESTAMP.IMPRINT.MISMATCH",
            "TIMESTAMP.RESPONSE.MALFORMED",
            "TIMESTAMP.RESPONSE.REJECTED",
            "TIMESTAMP.RESPONSE.TOO_LARGE",
            "TIMESTAMP.SIGNATURE.MALFORMED",
            "TIMESTAMP.SIGNATURE.NONE",
            "TIMESTAMP.TIME.FUTURE",
            "TIMESTAMP.TOKEN.DUPLICATE",
            "TIMESTAMP.TOKEN.MALFORMED",
            "TIMESTAMP.TOKEN.TOO_LARGE",
            "TIMESTAMP.TSA.EKU",
            "TIMESTAMP.TSA.EXPIRED",
            "TIMESTAMP.TSA.KEY_USAGE",
            "TIMESTAMP.TSA.REVOKED",
            "TIMESTAMP.TSA.UNKNOWN",
            "TIMESTAMP.TSA.UNTRUSTED",
        ),
        _TIMESTAMP,
    ),
    "TIMESTAMP.CMS.UNSUPPORTED": _LIMIT + "the timestamp token uses a form that this engine does not verify.",
    "TIMESTAMP.TOKEN.UNSUPPORTED_EXTENSION": _LIMIT
    + "the timestamp token has an extension that this engine does not verify.",
    "TIMESTAMP.TSA.UNSUPPORTED_CONSTRAINT": _LIMIT
    + "the certificate of the time-stamping authority has a constraint that this engine does not check.",
    "TIMESTAMP.OK": "None: the timestamp token verifies.",
    # --- TLS options ----------------------------------------------------------------------------
    **dict.fromkeys(
        (
            "TLS.CA_FILE.INVALID",
            "TLS.CLIENT_CERT.INCOMPLETE",
            "TLS.CLIENT_CERT.INVALID",
            "TLS.CLIENT_KEY.INVALID",
            "TLS.CLIENT_KEY.MISMATCH",
            "TLS.CLIENT_KEY.PASSPHRASE",
            "TLS.CONTEXT.UNUSABLE",
            "TLS.FILE.UNREADABLE",
        ),
        _TLS,
    ),
    "TLS.CLIENT_CERT.NO_AUTHORIZATION": (
        "Supply a signed authorization of the system owner with the client certificate."
    ),
    # --- Transport: no answer -------------------------------------------------------------------
    "TRANSPORT.BODY_ENCODED": "Serve the body without a content encoding that the engine does not decode.",
    "TRANSPORT.BODY_TRUNCATED": _LIMIT + "the body is larger than the transport limit. Serve a smaller body.",
    "TRANSPORT.DENIED": "No answer: the request was refused. Grant the test role access, then run again.",
    "TRANSPORT.RATE_LIMITED": (
        "No answer: the system limits the request rate. Run again later, or raise the limit."
    ),
    "TRANSPORT.REDIRECT_OUT_OF_SCOPE": (
        "No answer: a redirect leaves the authorized origins. Confirm the origin as the operator, or "
        "remove the redirect."
    ),
    "TRANSPORT.SERVER_ERROR": (
        "No answer: the server answered with a server error. Correct the server, then run again."
    ),
    "TRANSPORT.UNREACHABLE": (
        "No answer: the system is not reachable. Make the endpoint reachable, then run again."
    ),
    # --- Trust bundle ---------------------------------------------------------------------------
    "TRUST.BUNDLE.NOT_OBJECT": _TRUST,
    "TRUST.BUNDLE.OPTION": _TRUST,
    "TRUST.KEY.DUPLICATE_KID": _TRUST,
    "TRUST.KEY.NOT_P256": _TRUST,
    "TRUST.KEY.PERIOD_INVALID": _TRUST,
    "TRUST.KEY.PRIVATE": "Remove the private key material from the trust bundle.",
    "TRUST.KEY.ROLE_CONFLICT": _TRUST,
    "TRUST.MIGRATION.MALFORMED": _TRUST,
    "TRUST.MIGRATION.UNSCOPED_SERIAL": _TRUST,
    "TRUST.OUTPUT.EXISTS": _OUTPUT,
    "TRUST.SNAPSHOT.STALE": "Supply a trust bundle snapshot that is newer than its allowed age.",
    # --- Report validity ------------------------------------------------------------------------
    "VALIDITY.PERIOD.EXPIRED": (
        "Not a step result: the report is past its validity. Run the test again for a new report."
    ),
    "VALIDITY.PERIOD.NOT_STATED": "Not a step result: the report states no validity period.",
    "VALIDITY.PERIOD.OK": "None: the report is within its validity period.",
    "VALIDITY.REPORT.UNSIGNED": "Not a step result: sign the report, so that its validity can be checked.",
}


@dataclass(frozen=True)
class Hint:
    """One explanation for one step. ``kind`` is ``remediation`` for a fail, else ``next_step``."""

    kind: Literal["next_step", "remediation"]
    text: str


def hint_for_code(code: str) -> str | None:
    """The line for a reason code, or None if the table has no entry."""
    return HINTS.get(code)


def hint_for_step(result: TestResult) -> Hint | None:
    """The explanation for a step. None for a pass. Plain text: the caller escapes it."""
    if result.verdict is Verdict.PASS:
        return None
    kind: Literal["next_step", "remediation"] = (
        "remediation" if result.verdict is Verdict.FAIL else "next_step"
    )
    text = HINTS.get(result.reason_code)
    # A line that says nothing is to do fits a pass or an exclusion. A step that did not pass
    # with such a code gets the text of its execution status.
    if text is None or text.startswith("None:"):
        text = BY_STATUS[result.execution_status]
    return Hint(kind, text)


NO_INTERPRETATION: Final = (
    "No interpretation exists yet. A person must write one and a reviewer must approve it (open "
    "question OQ-002)."
)
NOT_APPROVED: Final = (
    "A reviewer approval of the interpretation is missing (open question OQ-002). Without it, "
    "reviewed mode cannot claim a pass."
)


def requirement_hint(result: RequirementResult, mode: ExecutionMode) -> str | None:
    """The missing interpretation or approval of an inconclusive requirement, else None."""
    if result.verdict is not Verdict.INCONCLUSIVE:
        return None
    if result.review_status is ReviewStatus.PLACEHOLDER:
        return NO_INTERPRETATION
    if mode is ExecutionMode.REVIEWED and result.review_status is not ReviewStatus.APPROVED:
        return NOT_APPROVED
    return None
