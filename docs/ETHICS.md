# Ethical Considerations

This artifact accompanies a measurement study of real-world phishing
infrastructure. Because the underlying dataset may contain sensitive
information and potentially unsafe executable components, we apply
additional safeguards to data handling, release, and artifact evaluation.


## Data Collection

The study analyzes phishing kits collected from real-world phishing
infrastructure.

The research did not recruit, contact, or interact with victims or phishing
operators as study participants. The collected artifacts were analyzed for
security research purposes in a controlled research environment.

The complete data-collection methodology and collection period are described
in `docs/PROVENANCE.md` and in the associated paper.


## Sensitive Information

During artifact preparation, we identified that some phishing kits and their
derived dynamic-analysis outputs may contain security-sensitive or identifying
information, including:

- victim-submitted usernames, email addresses, or passwords;
- attacker or developer email addresses and repository metadata;
- Telegram bot tokens, chat identifiers, or other authentication material;
- live URLs or infrastructure references;
- locally stored credential dumps; and
- potentially unsafe or executable components.

For this reason, the complete raw phishing-kit dataset and full per-kit
dynamic-analysis outputs are not distributed publicly.


## Public Artifact and Data Minimization

The public artifact includes only the data necessary to support evaluation
of the released methodology.

In particular, we release sanitized dynamic-analysis outputs for a subset
of 100 phishing kits. Sensitive values identified during the sanitization
process were redacted or replaced before public release.

The public subset is intended for scaled-down artifact evaluation and should
not be treated as a statistically representative substitute for the complete
study dataset.


## Restricted Dataset Access

The complete phishing-kit dataset and full per-kit analysis outputs are
available only through controlled access.

Qualified researchers may request access by submitting the Dataset Access
Request Form linked from the repository README.

Requests are reviewed individually based on institutional affiliation,
research purpose, intended use, and data-handling practices.

Recipients are expected not to redistribute the restricted dataset or use
credentials, tokens, identifiers, or infrastructure references contained in
the dataset to access external systems or identify or contact individuals.


## Handling and Storage

The original phishing-kit dataset was analyzed in a controlled research
environment.

Researchers working with restricted copies of the dataset should:

- restrict access to authorized researchers;
- store the data on access-controlled systems;
- avoid executing unknown components on production machines;
- use isolated environments when executing phishing-kit code;
- avoid unnecessary interaction with live infrastructure; and
- securely delete restricted copies when they are no longer required.


## Network and Execution Safety

Some phishing kits contain executable scripts and references to external
infrastructure.

The public artifact is designed so that evaluation does not require
interaction with active phishing infrastructure.

Code that supports live HTTP probing or execution of raw phishing-kit
components is released for methodological transparency, but such functions
should only be used in controlled environments and against systems for which
the researcher has authorization.


## Personally Identifiable Information

Personally identifiable information and security-sensitive values are not
intentionally included in the publicly released evaluation dataset.

Before release, the sampled data were reviewed and sanitized to remove or
redact sensitive values.

Because the underlying artifacts originate from real-world malicious
infrastructure, researchers who identify residual sensitive information in
the public artifact are asked to report it to the authors so that it can be
removed promptly.

## Responsible Handling of Findings

Potentially sensitive operational information discovered during the study
was handled conservatively and was not intentionally exposed through the
public artifact.

The paper reports findings only at the level necessary to support the
research claims, with sensitive identifiers redacted where appropriate.