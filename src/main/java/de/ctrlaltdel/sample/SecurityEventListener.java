package de.ctrlaltdel.sample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckEvent;

import java.security.Permission;
import java.security.Principal;
import java.util.function.Consumer;

public class SecurityEventListener implements Consumer<SecurityEvent> {

    private static final Logger LOG = LoggerFactory.getLogger("SecurityEvent");

    @Override
    public void accept(SecurityEvent securityEvent) {

        try {
            String eventName = securityEvent.getClass().getSimpleName();
            StringBuilder sb = new StringBuilder(eventName.replace("Event", ""));

            Principal principal = null;
            Permission permission = null;

            switch (eventName) {
                case "SecurityAuthenticationFailedEvent":
                    principal = ((SecurityAuthenticationFailedEvent) securityEvent).getPrincipal();
                    break;
                case "SecurityPermissionCheckFailedEvent":
                case "SecurityPermissionCheckSuccessfulEvent":
                    permission = ((SecurityPermissionCheckEvent) securityEvent).getPermission();
                    break;
            }

            new SecurityIdentityWrapper(securityEvent.getSecurityIdentity())
                    .appendPrincipal(sb, principal)
                    .appendRoles(sb);

            if (permission != null) {
                sb.append(" | Permission: ")
                  .append(permission.getClass().getSimpleName().replace("Permission", ""))
                  .append(' ').append(permission.getName());
            }

            LOG.info(sb.toString().trim());
        } catch (Throwable ignore) {
            // ignore
        }
    }
}
