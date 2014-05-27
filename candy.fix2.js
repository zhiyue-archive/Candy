//fix中文验证问题
Strophe.Connection.prototype.authenticate = function ()
{
    if (Strophe.getNodeFromJid(this.jid) === null &&
        this._authentication.sasl_anonymous) {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_success_handler = this._addSysHandler(
            this._sasl_success_cb.bind(this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            this._sasl_failure_cb.bind(this), null,
            "failure", null, null);

        this.send($build("auth", {
            xmlns: Strophe.NS.SASL,
            mechanism: "ANONYMOUS"
        }).tree());
    } else if (Strophe.getNodeFromJid(this.jid) === null) {
        // we don't have a node, which is required for non-anonymous
        // client connections
        this._changeConnectStatus(Strophe.Status.CONNFAIL,
            'x-strophe-bad-non-anon-jid');
        this.disconnect();
    /*} else if (this._authentication.sasl_scram_sha1) {
        var cnonce = MD5.hexdigest(Math.random() * 1234567890);

        var auth_str = "n=" + Strophe.getNodeFromJid(this.jid);
        auth_str += ",r=";
        auth_str += cnonce;

        this._sasl_data["cnonce"] = cnonce;
        this._sasl_data["client-first-message-bare"] = auth_str;

        auth_str = "n,," + auth_str;

        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_challenge_handler = this._addSysHandler(
            this._sasl_scram_challenge_cb.bind(this), null,
            "challenge", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            this._sasl_failure_cb.bind(this), null,
            "failure", null, null);

        this.send($build("auth", {
            xmlns: Strophe.NS.SASL,
            mechanism: "SCRAM-SHA-1"
        }).t(Base64.encode(auth_str)).tree());*/
    } else if (this._authentication.sasl_digest_md5) {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_challenge_handler = this._addSysHandler(
            this._sasl_digest_challenge1_cb.bind(this), null,
            "challenge", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            this._sasl_failure_cb.bind(this), null,
            "failure", null, null);

        this.send($build("auth", {
            xmlns: Strophe.NS.SASL,
            mechanism: "DIGEST-MD5"
        }).tree());
    } else if (this._authentication.sasl_plain) {
        // Build the plain auth string (barejid null
        // username null password) and base 64 encoded.
        auth_str = unescape(encodeURIComponent(Strophe.getBareJidFromJid(this.jid)));
        auth_str = auth_str + "\u0000";
        auth_str = auth_str + unescape(encodeURIComponent(Strophe.getNodeFromJid(this.jid)));
        auth_str = auth_str + "\u0000";
        auth_str = auth_str + this.pass;

        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._sasl_success_handler = this._addSysHandler(
            this._sasl_success_cb.bind(this), null,
            "success", null, null);
        this._sasl_failure_handler = this._addSysHandler(
            this._sasl_failure_cb.bind(this), null,
            "failure", null, null);

        hashed_auth_str = Base64.encode(auth_str);
        this.send($build("auth", {
            xmlns: Strophe.NS.SASL,
            mechanism: "PLAIN"
        }).t(hashed_auth_str).tree());
    } else {
        this._changeConnectStatus(Strophe.Status.AUTHENTICATING, null);
        this._addSysHandler(this._auth1_cb.bind(this), null, null,
            null, "_auth_1");

        this.send($iq({
            type: "get",
            to: this.domain,
            id: "_auth_1"
        }).c("query", {
                xmlns: Strophe.NS.AUTH
            }).c("username", {}).t(Strophe.getNodeFromJid(this.jid)).tree());
    }
}

