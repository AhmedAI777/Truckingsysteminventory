def ensure_auth():
    """Always keep users signed in across refreshes until they click Logout."""
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
        st.session_state.auth_role = None

    # --- Try restore from token in URL (works after refresh/new tab) ---
    if not st.session_state.auth_user:
        token = _get_query_auth()
        parsed = _parse_token(token) if token else None
        if parsed:
            u, r, exp = parsed
            st.session_state.auth_user = u
            st.session_state.auth_role = r

            # Auto-renew if expiring in < 3 days
            if exp - _now() < 3 * 86400:
                new_token = _make_token(u, r, ttl_days=30)
                _set_query_auth(new_token)
            return True

    # Already signed in for this runtime session?
    if st.session_state.auth_user and st.session_state.auth_role:
        return True

    # ---------- Login UI ----------
    st.markdown(f"# {APP_TITLE}")
    st.caption(SUBTITLE)
    st.info("Please sign in to continue.")

    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pw")
        submitted = st.form_submit_button("Login", type="primary")

    if submitted:
        role = authenticate(u.strip(), p)
        if role:
            st.session_state.auth_user = u.strip()
            st.session_state.auth_role = role

            # ALWAYS persist login: set signed token in URL (30 days) and auto-renew.
            token = _make_token(st.session_state.auth_user, role, ttl_days=30)
            _set_query_auth(token)

            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()
