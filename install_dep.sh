mvn package
mvn install:install-file -Dfile=target/SAML2Commons-1.0-SNAPSHOT.jar -DgroupId=com.bitium.saml -DartifactId=SAML2Commons -Dpackaging=jar -Dversion=1.0 -DgeneratePom=true