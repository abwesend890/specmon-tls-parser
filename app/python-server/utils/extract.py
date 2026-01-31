def extract_key_shares(parsed):
    messages = parsed.get("messages")
    key_share_entries = []
    if len(messages) == 0:
        return key_share_entries

    for msg in messages:
        client_hello = msg.get("client_hello")

        if not client_hello:
            continue

        for ext in client_hello.get("extensions", []):
            ks_ext = ext.get("key_share_extension")

            if ks_ext:
                entries = ks_ext.get("key_share_entry", [])
                key_share_entries.extend(entries)

    return key_share_entries