
Quick - Install:

- create module <JBOSS_HOME>/de/ctrlaltdel/sample/main :
```
<module xmlns="urn:jboss:module:1.1" name="de.ctrlaltdel.sample" slot="main">

    <resources>
        <resource-root path="elytron-listener.jar"/>
    </resources>

    <dependencies>
        <module name="org.wildfly.security.elytron"/>
        <module name="org.slf4j.impl"/>
        <module name="org.slf4j"/>
    </dependencies>
</module>
``` 

- standalone.xml: create Logger
```
  <logger category="SecurityEvent">
      <level name="INFO"/>
  </logger>
```
- standalone.xm: create custom security event listener
```
  <subsystem xmlns="urn:wildfly:elytron:8.0" final-providers="combined-providers" disallowed-providers="OracleUcrypto">
  ...
  <audit-logging>
     ... 
    <custom-security-event-listener name="sample-listener" module="de.ctrlaltdel.sample" class-name="de.ctrlaltdel.sample.SecurityEventListener"/>
  </audit-logging>
  <security-domains>
      <security-domain name="ApplicationDomain" default-realm="ApplicationRealm" permission-mapper="default-permission-mapper" security-event-listener="sample-listener" >
       ...
      <security-domain name="ManagementDomain" default-realm="ManagementRealm" permission-mapper="default-permission-mapper" security-event-listener="sample-listener" >
       ...
  </security-domains>
```

=> Log:
```
... INFO  [SecurityEvent] (management task-1) SecurityPermissionCheckSuccessful | Principal: $local | Roles: SuperUser | Permission: Login
... INFO  [SecurityEvent] (management task-1) SecurityAuthenticationSuccessful | Principal: $local | Roles: SuperUser

... INFO  [SecurityEvent] (default task-2) SecurityPermissionCheckSuccessful | Principal: anonymous | Permission: Login
... INFO  [SecurityEvent] (default task-2) SecurityPermissionCheckSuccessful | Principal: daniel | Roles: ... | Permission: Login
```

License: WTFPL <http://www.wtfpl.net>
