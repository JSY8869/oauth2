package oauth.kakao.security.handler.success;

import lombok.RequiredArgsConstructor;
import oauth.kakao.config.AppProperties;
import oauth.kakao.exception.BadRequestException;
import oauth.kakao.security.HttpCookieOAuth2AuthorizationRequestRepository;
import oauth.kakao.security.auth.UserPrincipal;
import oauth.kakao.security.token.domain.JwtAccessToken;
import oauth.kakao.security.token.domain.JwtRefreshToken;
import oauth.kakao.security.token.provider.JwtTokenProvider;
import oauth.kakao.util.CookieUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static oauth.kakao.security.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@RequiredArgsConstructor
public class OAuthAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AppProperties appProperties;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final JwtTokenProvider tokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("response has already been commited. unable to redirect to " + targetUrl);
            return;
        }
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectedUri(redirectUri.get())) {
            throw new BadRequestException("unauthorized Redirect URI");
        }

        String targetUri = redirectUri.orElse(getDefaultTargetUrl());

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();;
        JwtAccessToken jwtAccessToken = tokenProvider.issueAccessToken(userPrincipal);
        JwtRefreshToken jwtRefreshToken = tokenProvider.issueRefreshToken(userPrincipal);

        response.addHeader("AccessToken", jwtAccessToken.getValue());
        response.addHeader("RefreshToken", jwtRefreshToken.getValue());
        return UriComponentsBuilder.fromUriString(targetUri)
                .queryParam("error", "")
                .build().toString();
    }

    private boolean isAuthorizedRedirectedUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost()) &&
                            authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}
