package de.ctrlaltdel.sample;

import org.wildfly.security.auth.server.SecurityIdentity;

import java.security.Principal;

class SecurityIdentityWrapper {

    private final SecurityIdentity identity;

    SecurityIdentityWrapper(SecurityIdentity identity) {
        this.identity = identity;
    }

    SecurityIdentityWrapper appendPrincipal(StringBuilder sb, Principal principal) {
        if (identity == null) {
            return this;
        }
        if (principal == null) {
            principal = identity.getPrincipal();
        }
        if (principal != null) {
            sb.append(" | Principal: ").append(principal.getName());
        }
        return this;
    }


    SecurityIdentityWrapper appendRoles(StringBuilder sb) {
        if (identity == null) {
            return this;
        }
        if (identity.getRoles() == null) {
            return this;
        }
        if (identity.getRoles().isEmpty()) {
            return this;
        }
        sb.append(" | Roles:");
        for (String role: identity.getRoles()) {
            sb.append(' ').append(role);
        }
        return this;
    }
}
