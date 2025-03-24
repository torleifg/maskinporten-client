# Maskinporten

### Prerequisites

* Test and/or production Maskinporten Client
* Test and/or production JWKS file or PKCS #12 file (Buypass or Commfides)

### Installation

Clone repository and install artifact in Maven local repository.

### Usage

```
<dependency>
  <groupId>com.github.torleifg</groupId>
  <artifactId>maskinporten-client</artifactId>
  <version>0.2.0-SNAPSHOT</version>
</dependency>
```

#### JWKS

```java
import com.github.torleifg.maskinporten.MaskinportenClient;

public class Application {
    
    public static void main(String[] args) {
        final MaskinportenClient client = MaskinportenJwksClient.builder()
                .wellKnown("https://test.maskinporten.no/")
                .clientId("clientId")
                .jwks(jwks)
                .kid("kid")
                .cache(false)
                .build();

        client.getAccessToken(scope).ifPresent(System.out::println);
    }
}
```

#### X509

```java
import com.github.torleifg.maskinporten.MaskinportenClient;

public class Application {
    
    public static void main(String[] args) {
        final MaskinportenClient client = MaskinportenX509Client.builder()
                .wellKnown("https://test.maskinporten.no/")
                .clientId("clientId")
                .certificate(x509Certificate)
                .key(privateKey)
                .cache(false)
                .build();

        client.getAccessToken(scope).ifPresent(System.out::println);
    }
}
```
