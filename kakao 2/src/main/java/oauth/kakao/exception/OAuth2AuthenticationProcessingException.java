package oauth.kakao.exception;

import javax.security.sasl.AuthenticationException;

public class OAuth2AuthenticationProcessingException extends AuthenticationException {

    public OAuth2AuthenticationProcessingException(String message, Throwable cause) {
        super(message, cause);
    }

    public OAuth2AuthenticationProcessingException(String message) {
        super(message);
    }
}
