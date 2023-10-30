package oauth.kakao.security.handler.logout;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // SecurityContextHolder clear
        SecurityContextHolder.clearContext();
        //TODO Redis를 이용한 로그아웃 토큰 저장 로직 필요
    }
}
