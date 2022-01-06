# Maskinporten

### Prerequisites

* Test and/or production Maskinporten Client
* Test and/or production JWKS file or PKCS #12 file (Buypass or Commfides)

### Installation

```
<dependency>
  <groupId>com.github.torleifg</groupId>
  <artifactId>maskinporten-client</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

### Usage

#### JWKS

```java
import com.github.torleifg.maskinporten.MaskinportenClient;

public class Application {
    public static void main(String[] args) {
        final MaskinportenClient client = MaskinportenJwksClient.builder()
                .wellKnown("https://ver2.maskinporten.no/")
                .clientId(clientId)
                .jwks(jwks)
                .kid(kid)
                .cache(false)
                .build();

        var token = client.getAccessToken(scope);

        System.out.println(token);
    }
}
```

#### X509

```java
import com.github.torleifg.maskinporten.MaskinportenClient;

public class Application {
    public static void main(String[] args) {
        final MaskinportenClient client = MaskinportenX509Client.builder()
                .wellKnown("https://ver2.maskinporten.no/")
                .clientId(clientId)
                .certificate(x509Certificate)
                .key(privateKey)
                .cache(false)
                .build();

        var token = client.getAccessToken(scope);

        System.out.println(token);
    }
}
```