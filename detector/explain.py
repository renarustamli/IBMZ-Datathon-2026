"""Plain-English explanation of a detector alert, for non-experts watching the dashboard.

  explain(note, result) -> one or two sentences

Template-based for now (no model API key yet). To switch to a language model, make
llm_explain() call it with the prompt it builds, and keep the template as the fallback.
"""

# What each alert factor means for the data, in plain words.
PLAIN = {
    "pqc_stripped": "someone removed the quantum-safe options from this client's connection request, "
                    "forcing it onto old encryption that a future quantum computer could break",
    "pqc_offered_not_chosen": "the client asked for quantum-safe encryption but the connection ended up "
                              "on old encryption, which suggests someone tampered with the handshake",
    "chosen_pqc": "this connection uses old encryption that a future quantum computer could break",
    "offers_pqc": "this client did not ask for quantum-safe encryption at all",
    "strength_drop": "this client's encryption is weaker than it normally uses, a quiet way to downgrade security",
    "cipher_strength": "the connection uses a weak, outdated cipher",
    "tls13": "the client is using an older version of the security protocol than normal traffic",
    "conn_per_min": "this client is connecting far more often than normal, like a script trying to grab data",
    "conn_per_10min": "this client has made an unusually large number of connections in the last few minutes",
    "new_group_set": "this client suddenly asked for a different set of encryption options than it ever has",
    "n_groups": "the connection request lists an unusual set of encryption options, typical of a scanning tool",
    "hour": "this activity is happening at an unusual time of day",
}


def explain(note, result):
    if result.get("by") == "watch":
        return (f"{note.get('client_id', 'A client')} connected once without quantum-safe encryption. "
                "Real devices occasionally do this harmlessly, so it is being watched; "
                "a repeat within 10 minutes raises an alarm.")
    if not result.get("alert"):
        return "Normal, quantum-safe traffic." if note.get("strong_or_weak") == "strong" \
            else "Normal traffic from a client that only supports older encryption."
    try:
        return llm_explain(note, result)
    except NotImplementedError:
        return template_explain(note, result)


def template_explain(note, result):
    parts = [PLAIN[f] for f in result.get("factors", []) if f in PLAIN]
    who = note.get("client_id", "a client")
    if not parts:
        text = f"The AI model found {who}'s connection unlike any normal traffic it has learned."
    else:
        text = f"{who}: {parts[0][0].upper()}{parts[0][1:]}."
        if len(parts) > 1:
            text += " Also, " + "; ".join(parts[1:]) + "."
    if result.get("by") == "model":
        text += " (Spotted by the AI model, not a fixed rule.)"
    if result.get("blocked"):
        text += " The gateway refused the connection, so no data was exposed."
    if result.get("prior_downgrades"):
        text += " This client was already caught in a downgrade earlier."
    return text


def llm_explain(note, result):
    """Hook for a language model (e.g. IBM watsonx or Claude). Prompt to send:
       f"Explain this TLS security alert to a non-technical bank manager in two sentences.
         Connection: {note}. Detector finding: {result['reason']}."
    """
    raise NotImplementedError
