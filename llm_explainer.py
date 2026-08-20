"""
llm_explainer.py

Takes the output of analyze_email() + extract_features() + a trained model's
prediction, and produces a plain-language explanation of *why* an email was
classified the way it was. Uses a local Ollama model (qwen3.5:9b) as the
explanation engine — the LLM never re-classifies the email itself, it only
narrates the evidence the ML model already used.

Usage (once wired into analyze.py's __main__ or a CLI):

    from llm_explainer import explain_verdict

    data = analyze_email(filepath, verbose=False)
    features = extract_features(data)
    prediction = model.predict([list(features.values())])[0]
    probability = model.predict_proba([list(features.values())])[0][1]

    explanation = explain_verdict(data, features, prediction, probability)
    print(explanation)
"""

import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen3.5:9b"


def _build_prompt(email_data, features, prediction, probability):
    """
    Build a structured prompt from already-extracted evidence — not the raw
    email body — so the LLM explains the model's actual reasoning rather
    than freelancing its own read of the email.
    """
    verdict = "PHISHING" if prediction == 1 else "LEGITIMATE"

    # Pull out only the human-relevant signals, skip zero/empty ones so the
    # prompt doesn't get cluttered with a wall of "X: 0" lines.
    signals = []

    if features.get("brand_mismatch"):
        matched_brand = email_data["display_name_results"].get("matched_brand")
        signals.append(
            f"- Display name claims to be from '{matched_brand}' but the "
            f"sending domain does not match {matched_brand}'s real domain."
        )
    if features.get("embedded_address_mismatch"):
        signals.append(
            "- The display name contains an embedded email address that "
            "differs from the actual sending address."
        )
    if features.get("generic_authority_sender"):
        signals.append(
            f"- Sender uses a generic authority title "
            f"('{email_data['display_name_results'].get('display_name')}') "
            f"instead of a real identifiable person or company."
        )
    if features.get("suspicious_local_part"):
        signals.append(
            "- Sending address has a long, digit-heavy local part typical "
            "of auto-generated spam infrastructure."
        )
    if features.get("reply_to_mismatch"):
        signals.append(
            f"- Reply-To domain differs from the From domain "
            f"(From: {email_data['sender']!r}, Reply-To: {email_data['reply_to']!r})."
        )
    if features.get("homograph_domain"):
        signals.append(
            "- Sending domain is a near-lookalike (typosquat) of a known "
            "brand's legitimate domain."
        )
    if features.get("num_urgency_keywords", 0) > 0:
        kws = ", ".join(email_data.get("urgency_keywords_found", []))
        signals.append(
            f"- Urgency/pressure language found in subject or body: {kws}."
        )
    if features.get("num_link_mismatches", 0) > 0:
        signals.append(
            f"- {features['num_link_mismatches']} link(s) where the visible "
            f"text domain doesn't match the actual href destination."
        )
    auth = email_data.get("auth_results", {})
    failed_auth = [k.upper() for k in ("spf", "dkim", "dmarc") if auth.get(k) != "pass"]
    if failed_auth:
        signals.append(f"- Failed authentication checks: {', '.join(failed_auth)}.")

    if not signals:
        signals.append(
            "- No strong individual red flags fired; classification is "
            "based on the overall combination of weaker signals."
        )

    signals_text = "\n".join(signals)

    prompt = f"""You are explaining an email phishing classifier's decision to a non-technical user.

Email subject: {email_data.get('subject', '(none)')!r}
Sender: {email_data.get('sender', '(none)')!r}

Model verdict: {verdict} (confidence: {probability:.0%})

Evidence the model used:
{signals_text}

Write a short (2-4 sentence) plain-language explanation of why this email
was flagged this way. Be concrete about which evidence mattered most.
Do not invent evidence that isn't listed above. Do not use technical
jargon like "feature vector" or "coefficient" — write for someone who
just wants to know if they should trust this email."""

    return prompt


def _template_fallback(email_data, features, prediction, probability):
    """
    Degrade gracefully when Ollama isn't running — a plain templated
    explanation instead of crashing the whole pipeline.
    """
    verdict = "phishing" if prediction == 1 else "legitimate"
    reasons = []
    if features.get("brand_mismatch"):
        reasons.append("it impersonates a known brand from an unrelated domain")
    if features.get("num_urgency_keywords", 0) > 0:
        reasons.append("it uses urgency/pressure language")
    if features.get("num_link_mismatches", 0) > 0:
        reasons.append("its links don't go where they claim to")
    if features.get("generic_authority_sender"):
        reasons.append("it comes from a generic 'support' style sender")

    if not reasons:
        reason_text = "no single strong red flag, but the combination of weaker signals"
    else:
        reason_text = ", and ".join(reasons)

    return (
        f"[Fallback explanation — Ollama unavailable] "
        f"This email was classified as {verdict} ({probability:.0%} confidence) "
        f"because {reason_text}."
    )


def explain_verdict(email_data, features, prediction, probability, timeout=30):
    """
    Main entry point. Returns a plain-language explanation string.
    Falls back to a template if Ollama can't be reached.
    """
    prompt = _build_prompt(email_data, features, prediction, probability)

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
        return result.get("response", "").strip()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"[llm_explainer] Ollama call failed ({e}), using fallback.")
        return _template_fallback(email_data, features, prediction, probability)


if __name__ == "__main__":
    # Quick manual test against a known FN-fixed file, once model + features
    # are wired in from analyze.py / train.py.
    # Placeholder demo using fake data so this file runs standalone:
    fake_email_data = {
        "subject": "Your account has been suspended",
        "sender": "PayPal Security <security@paypa1-verify.com>",
        "reply_to": "",
        "display_name_results": {
            "display_name": "PayPal Security",
            "matched_brand": "paypal",
        },
        "urgency_keywords_found": ["suspended", "immediately"],
        "auth_results": {"spf": "fail", "dkim": "none", "dmarc": "none"},
    }
    fake_features = {
        "brand_mismatch": 1,
        "embedded_address_mismatch": 0,
        "generic_authority_sender": 0,
        "suspicious_local_part": 0,
        "reply_to_mismatch": 0,
        "homograph_domain": 1,
        "num_urgency_keywords": 2,
        "num_link_mismatches": 0,
    }
    print(explain_verdict(fake_email_data, fake_features, prediction=1, probability=0.94))