package com.github.torleifg.maskinporten;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WireMockTest
class MaskinportenClientTests {

    @Test
    void okTest(WireMockRuntimeInfo mockRuntimeInfo) {
        var baseUrl = mockRuntimeInfo.getHttpBaseUrl();

        stubFor(get("/.well-known/oauth-authorization-server").willReturn(okJson(String.format("""
                    {
                      "issuer": "%s",
                      "token_endpoint": "%s/token"
                    }
                """, baseUrl, baseUrl))));

        var client = MaskinportenJwksClient.builder()
                .wellKnown(baseUrl)
                .clientId("clientId")
                .jwks(getValidJwks())
                .kid("kid")
                .cache(false)
                .build();

        stubFor(post("/token").willReturn(okJson("""
                {
                  "access_token": "token"
                }
                """)));

        var accessToken = client.getAccessToken("scope");

        assertTrue(accessToken.isPresent());
    }

    @Test
    void exceptionTest(WireMockRuntimeInfo mockRuntimeInfo) {
        var baseUrl = mockRuntimeInfo.getHttpBaseUrl();

        stubFor(get("/.well-known/oauth-authorization-server").willReturn(okJson(String.format("""
                    {
                      "issuer": "%s",
                      "token_endpoint": "%s/token"
                    }
                """, baseUrl, baseUrl))));

        assertThrows(MaskinportenClientException.class, () -> MaskinportenJwksClient.builder()
                .wellKnown(baseUrl)
                .clientId("clientId")
                .jwks(getValidJwks())
                .kid("invalid")
                .cache(false)
                .build());
    }

    String getValidJwks() {
        return """
                {
                    "keys": [
                        {
                            "alg": "RS256",
                            "d": "M-RDRF-4wA9x3fHMbQKFBCYvBvXYxIC7gyQWxP7vJFyOV-4D2kxE8TF0Q36auKwf0YXdXYHxG_sQBnHYGSKd_yZIVmOI0RHOKwQf-AJ0IP6UHVWbHiE9LzOMsQNTAAdzMYUOZeszFnml8YDyOJtOKXH37B2OzHX4X25QHiyWbL6iLcaKdO_MWW10YmTBaxerTG7-ITAZRoR7eSe7he5wGjnW4OQ-FgyAvLP4F7ZCWFK6ddDjdVY_cvSifIrNeDdI32tq-OlCoqjXmrhZ3ABtu-T7WFhgQQQvMLe0pCK_LZBc0WwVydbUCmU17Pi_Y8JKlaVTX5RxuJRHvmBmfGRiCQ",
                            "dp": "Q2ytPQk1UXwKsuuZYku7c63oUsJhCInmoYw3xAz9zfRnpCFoir_agE5tpu3YqlQVOE0TswesMWhb7-XpJRZlRsUcQCtzXAnJlClgkwDV1VV7UKm9tr_C0Vfid_H4ghssAgndYaWOBu5FZeyhFnPJD395l6EBFnt8Ag0Fgd9XHqc",
                            "dq": "YR7bOfcK2WclWsu8bOnBf90b6O2BbV9tONJCiqc9hgU2gea4MmcL-D-oD7bOEcvnSkPxQ9Z32TCOgKUNJDirRroqcW5S6JK6KY3wl1KAkgWafIjfOBrpRIbzdyWcAv_UUP7fUqldwg1aLRAQm1766ivW6EA65xBMVgQdDJ_Y1G0",
                            "e": "AQAB",
                            "kid": "kid",
                            "kty": "RSA",
                            "n": "u_v4JCejSBm5k9sSa-XvT8jM-YRnckm5q1hQKjFxxpJ_cqsFpoqGQQrKDo8mv5y5yyDptCu7_aAHuCQXiERdIvEmD4kffmq2smp70gQpieFPB8PH9aWRQ1M_OBRSEJdJwL_-y_2UkDvyvjKgk1vHLnVilshF_VJ_Ag_B6egYBLg-pfOB3D1Nj00TAnb6yg_S5dKcguRfwxyey6p28zCljVU9wlH9AfiB1ZC2S3SINmWDygVnz5kwaS3MZfSh0Ud-_IQvjuQl6Z9Caw79ygA_ZdE8efeJ8aXhhesGQGMrWthcGUaS7CYDSnNwIAH8AnNJRjHZFEiuEvQKn2NvMkIC-w",
                            "p": "5wxj_Jsk4vwbdBIZ93mUBhGJAsDiT0FgrU02Y63xt4GbiOHMMyNr9QlGkuMYUvKDvxVuLbCqmc7kjK5LdGiZoQVT56JZD6LpSK7u4ofEpoIJXzMEhHvdX298f1R0uUCxuUTH68zc0NHWX5LeAGnLHgEcuhhKhjY-vt2vzinNnc8",
                            "q": "0EkE1y4SwIJFu0yNlKwfRwTZONn2QZnWEMzm4mJ3sBIQ1LELnKO-nj4tryZw-v-h0xMnoYCliAZMDwIeHlLye4JifwWoUIkkO-GgF1kf4Tk2YLfcjkNqLUFziANxwnWgn6nRUXDeuqd2f99GlxrrIAybwBdZQOiUoa84Blc4HxU",
                            "qi": "XW40FHxsUEtjMqha7YA6NY1GLJug8nbYzPuYkk8bIeh69n5UCa7yclVlMimug0l89fy1wyWU-GW90pL-7c_ziAq9X2ZclUycXwMjLHIzadRAk81c5Rfjf4QLA86wxvDmJpLG1LMuIQsj7Kk4sh17LqrtQjz8iM5K9xegVsPQ0GM",
                            "use": "sig"
                        }
                    ]
                }
                """;
    }
}
